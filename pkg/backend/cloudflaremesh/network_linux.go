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

type meshNetwork struct {
	lease          *lease.Lease
	sm             subnet.Manager
	routes         localRouteManager
	reconcileEvery time.Duration
	desiredMu      sync.Mutex
	desired        map[string]struct{}
}

func (n *meshNetwork) Lease() *lease.Lease { return n.lease }
func (n *meshNetwork) MTU() int            { return n.routes.MTU() }

func (n *meshNetwork) Run(ctx context.Context) {
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

func (n *meshNetwork) handleEvents(batch []lease.Event) {
	for _, event := range batch {
		if event.Lease.Attrs.BackendType != meshapi.BackendName {
			log.Warningf("cloudflare-mesh: ignoring subnet %s from backend %q", event.Lease.Subnet, event.Lease.Attrs.BackendType)
			continue
		}
		network := event.Lease.Subnet.String()
		switch event.Type {
		case lease.EventAdded:
			if err := n.routes.Ensure(network); err != nil {
				log.Errorf("cloudflare-mesh: %v", err)
				continue
			}
			n.desiredMu.Lock()
			n.desired[network] = struct{}{}
			n.desiredMu.Unlock()
		case lease.EventRemoved:
			if err := n.routes.Remove(network); err != nil {
				log.Errorf("cloudflare-mesh: %v", err)
				continue
			}
			n.desiredMu.Lock()
			delete(n.desired, network)
			n.desiredMu.Unlock()
		}
	}
}

func (n *meshNetwork) reconcile() {
	n.desiredMu.Lock()
	desired := make([]string, 0, len(n.desired))
	for network := range n.desired {
		desired = append(desired, network)
	}
	n.desiredMu.Unlock()
	for _, network := range desired {
		if err := n.routes.Ensure(network); err != nil {
			log.Errorf("cloudflare-mesh: reconcile route: %v", err)
		}
	}
}
