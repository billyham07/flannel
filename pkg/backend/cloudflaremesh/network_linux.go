// Copyright 2026 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !windows

package cloudflaremesh

import (
	"context"
	"sync"
	"time"

	meshapi "github.com/flannel-io/flannel/pkg/cloudflaremesh"
	"github.com/flannel-io/flannel/pkg/lease"
	"github.com/flannel-io/flannel/pkg/subnet"
	log "k8s.io/klog/v2"
)

// pruneGrace is how long Run waits before it trusts its view of the cluster
// enough to delete routes. WatchLeases stays silent when the local node is the
// only one holding a lease, so an empty desired set is indistinguishable from
// "the first snapshot has not arrived yet" until this has elapsed.
const pruneGrace = time.Minute

// meshTransport is the part of the MASQUE session meshNetwork owns for teardown.
type meshTransport interface {
	Close()
}

type meshNetwork struct {
	lease          *lease.Lease
	sm             subnet.Manager
	routes         localRouteManager
	transport      meshTransport
	reconcileEvery time.Duration
	now            func() time.Time
	desiredMu      sync.Mutex
	desired        map[string]struct{}
	synced         bool
	prunableAt     time.Time
}

func (n *meshNetwork) Lease() *lease.Lease { return n.lease }
func (n *meshNetwork) MTU() int            { return n.routes.MTU() }

func (n *meshNetwork) Run(ctx context.Context) {
	defer n.shutdown()
	n.prunableAt = n.clock().Add(pruneGrace)

	events := make(chan []lease.Event)
	go subnet.WatchLeases(ctx, n.sm, n.lease, events)
	ticker := time.NewTicker(n.reconcileEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-events:
			if !ok {
				return
			}
			n.handleEvents(batch)
		case <-ticker.C:
			n.reconcile()
		}
	}
}

// shutdown returns the host to its pre-flannel state. flanneld blocks on Run
// through its WaitGroup before exiting, so this is the backend's only teardown
// hook: routes go first because Cleanup must not race the disappearance of the
// TUN device the transport owns.
func (n *meshNetwork) shutdown() {
	if err := n.routes.Cleanup(); err != nil {
		log.Errorf("cloudflare-mesh: clean up routing state: %v", err)
	}
	if n.transport != nil {
		n.transport.Close()
	}
}

func (n *meshNetwork) clock() time.Time {
	if n.now != nil {
		return n.now()
	}
	return time.Now()
}

func (n *meshNetwork) handleEvents(batch []lease.Event) {
	defer func() {
		n.desiredMu.Lock()
		n.synced = true
		n.desiredMu.Unlock()
	}()
	for _, event := range batch {
		if event.Lease.Attrs.BackendType != meshapi.BackendName {
			log.Warningf("cloudflare-mesh: ignoring subnet %s from backend %q", event.Lease.Subnet, event.Lease.Attrs.BackendType)
			continue
		}
		network := event.Lease.Subnet.String()
		// The desired set is updated even when the netlink call fails: it
		// records what the cluster wants, and the periodic reconcile is what
		// retries. Dropping the entry here would strand the lease until it
		// changed again.
		switch event.Type {
		case lease.EventAdded:
			n.desiredMu.Lock()
			n.desired[network] = struct{}{}
			n.desiredMu.Unlock()
			if err := n.routes.Ensure(network); err != nil {
				log.Errorf("cloudflare-mesh: %v", err)
			}
		case lease.EventRemoved:
			n.desiredMu.Lock()
			delete(n.desired, network)
			n.desiredMu.Unlock()
			if err := n.routes.Remove(network); err != nil {
				log.Errorf("cloudflare-mesh: %v", err)
			}
		}
	}
}

func (n *meshNetwork) reconcile() {
	n.desiredMu.Lock()
	desired := make(map[string]struct{}, len(n.desired))
	for network := range n.desired {
		desired[network] = struct{}{}
	}
	synced := n.synced
	n.desiredMu.Unlock()

	// Pruning against a desired set we do not trust yet would blackhole every
	// remote PodCIDR, so re-assert the known routes and wait.
	if !synced && n.clock().Before(n.prunableAt) {
		for network := range desired {
			if err := n.routes.Ensure(network); err != nil {
				log.Errorf("cloudflare-mesh: reconcile route: %v", err)
			}
		}
		return
	}
	if err := n.routes.Reconcile(desired); err != nil {
		log.Errorf("cloudflare-mesh: reconcile routes: %v", err)
	}
}
