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
	"errors"
	"net"
	"reflect"
	"slices"
	"testing"
	"time"

	meshapi "github.com/flannel-io/flannel/pkg/cloudflaremesh"
	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/pkg/lease"
)

type fakeRouteManager struct {
	calls      []string
	ensured    []string
	reconciled []map[string]struct{}
	ensureErr  error
	cleanupErr error
}

func (f *fakeRouteManager) Ensure(network string) error {
	f.calls = append(f.calls, "ensure")
	f.ensured = append(f.ensured, network)
	return f.ensureErr
}

func (f *fakeRouteManager) Remove(network string) error {
	f.calls = append(f.calls, "remove")
	return nil
}

func (f *fakeRouteManager) Reconcile(desired map[string]struct{}) error {
	f.calls = append(f.calls, "reconcile")
	f.reconciled = append(f.reconciled, desired)
	return nil
}

func (f *fakeRouteManager) Cleanup() error {
	f.calls = append(f.calls, "cleanup")
	return f.cleanupErr
}

func (f *fakeRouteManager) MeshIP() net.IP { return net.ParseIP("100.96.1.2").To4() }
func (f *fakeRouteManager) MTU() int       { return 1280 }
func (f *fakeRouteManager) Table() int     { return 51820 }

type fakeTransport struct {
	calls  *[]string
	closed int
}

func (f *fakeTransport) Close() {
	*f.calls = append(*f.calls, "transport-close")
	f.closed++
}

func mustLease(t *testing.T, subnet, backendType string) lease.Lease {
	t.Helper()
	_, network, err := net.ParseCIDR(subnet)
	if err != nil {
		t.Fatal(err)
	}
	return lease.Lease{Subnet: ip.FromIPNet(network), Attrs: lease.LeaseAttrs{BackendType: backendType}}
}

func newTestMeshNetwork(routes localRouteManager, now time.Time) *meshNetwork {
	return &meshNetwork{
		routes:     routes,
		now:        func() time.Time { return now },
		desired:    make(map[string]struct{}),
		prunableAt: now.Add(pruneGrace),
	}
}

// WatchLeases stays silent on a single-node cluster, so an empty desired set
// must not be treated as authoritative until the grace period has passed.
func TestReconcileDoesNotPruneBeforeFirstSnapshot(t *testing.T) {
	routes := &fakeRouteManager{}
	start := time.Now()
	network := newTestMeshNetwork(routes, start)
	network.desired["10.10.133.0/24"] = struct{}{}

	network.reconcile()
	if slices.Contains(routes.calls, "reconcile") {
		t.Fatalf("pruned before the first snapshot: %v", routes.calls)
	}
	if want := []string{"10.10.133.0/24"}; !reflect.DeepEqual(routes.ensured, want) {
		t.Fatalf("ensured = %v, want %v", routes.ensured, want)
	}

	network.now = func() time.Time { return start.Add(pruneGrace + time.Second) }
	network.reconcile()
	if !slices.Contains(routes.calls, "reconcile") {
		t.Fatalf("did not prune after the grace period: %v", routes.calls)
	}
}

func TestReconcilePrunesOnceLeasesAreKnown(t *testing.T) {
	routes := &fakeRouteManager{}
	network := newTestMeshNetwork(routes, time.Now())

	network.handleEvents([]lease.Event{{Type: lease.EventAdded, Lease: mustLease(t, "10.10.133.0/24", meshapi.BackendName)}})
	network.reconcile()

	if len(routes.reconciled) != 1 {
		t.Fatalf("expected one reconcile, got %v", routes.calls)
	}
	want := map[string]struct{}{"10.10.133.0/24": {}}
	if !reflect.DeepEqual(routes.reconciled[0], want) {
		t.Fatalf("reconciled with %v, want %v", routes.reconciled[0], want)
	}
}

// A lease whose route could not be installed still belongs to the desired
// set, otherwise nothing would ever retry it.
func TestFailedEnsureIsRetriedByReconcile(t *testing.T) {
	routes := &fakeRouteManager{ensureErr: errors.New("netlink is unhappy")}
	network := newTestMeshNetwork(routes, time.Now())

	network.handleEvents([]lease.Event{{Type: lease.EventAdded, Lease: mustLease(t, "10.10.133.0/24", meshapi.BackendName)}})
	network.reconcile()

	want := map[string]struct{}{"10.10.133.0/24": {}}
	if len(routes.reconciled) != 1 || !reflect.DeepEqual(routes.reconciled[0], want) {
		t.Fatalf("reconciled = %v, want one entry %v", routes.reconciled, want)
	}
}

// A batch carrying only foreign backends still establishes the watch, so a
// node with no mesh peers left must become prunable rather than keep stale
// routes forever.
func TestReconcilePrunesAfterForeignBackendBatch(t *testing.T) {
	routes := &fakeRouteManager{}
	network := newTestMeshNetwork(routes, time.Now())

	network.handleEvents([]lease.Event{{Type: lease.EventAdded, Lease: mustLease(t, "10.10.133.0/24", "vxlan")}})
	network.reconcile()

	if len(routes.reconciled) != 1 || len(routes.reconciled[0]) != 0 {
		t.Fatalf("expected one reconcile with an empty desired set, got %v", routes.reconciled)
	}
}

func TestShutdownCleansRoutesBeforeClosingTransport(t *testing.T) {
	routes := &fakeRouteManager{}
	transport := &fakeTransport{calls: &routes.calls}
	network := newTestMeshNetwork(routes, time.Now())
	network.transport = transport

	network.shutdown()

	if want := []string{"cleanup", "transport-close"}; !reflect.DeepEqual(routes.calls, want) {
		t.Fatalf("shutdown order = %v, want %v", routes.calls, want)
	}
}

// A wedged routing table must not stop the tunnel from being torn down.
func TestShutdownClosesTransportEvenWhenCleanupFails(t *testing.T) {
	routes := &fakeRouteManager{cleanupErr: errors.New("netlink is unhappy")}
	transport := &fakeTransport{calls: &routes.calls}
	network := newTestMeshNetwork(routes, time.Now())
	network.transport = transport

	network.shutdown()

	if transport.closed != 1 {
		t.Fatalf("transport closed %d times, want 1", transport.closed)
	}
}
