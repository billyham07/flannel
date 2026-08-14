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

package cloudflaremeshoperator

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	meshapi "github.com/flannel-io/flannel/pkg/cloudflaremesh"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

type fakeMeshAPI struct {
	connectors           map[string]*meshapi.ConnectorCredentials
	routes               []meshapi.Route
	registrations        []meshapi.DeviceRegistration
	ensureRoutes         int
	deleted              []string
	deletedConnectors    []string
	deletedRegistrations []string
	listedRegistrations  int
	listErr              error
}

func (f *fakeMeshAPI) EnsureConnector(_ context.Context, connectorID, name string, _ bool) (*meshapi.ConnectorCredentials, error) {
	if connectorID != "" {
		for _, connector := range f.connectors {
			if connector.ID == connectorID {
				return connector, nil
			}
		}
	}
	if connector, ok := f.connectors[name]; ok {
		return connector, nil
	}
	connector := &meshapi.ConnectorCredentials{ID: "id-" + name, Name: name, Token: "token-" + name}
	f.connectors[name] = connector
	return connector, nil
}

func (f *fakeMeshAPI) ListConnectors(_ context.Context) ([]meshapi.ConnectorCredentials, error) {
	connectors := make([]meshapi.ConnectorCredentials, 0, len(f.connectors))
	for _, connector := range f.connectors {
		connectors = append(connectors, *connector)
	}
	return connectors, nil
}

func (f *fakeMeshAPI) DeleteConnector(_ context.Context, connectorID string) error {
	f.deletedConnectors = append(f.deletedConnectors, connectorID)
	for name, connector := range f.connectors {
		if connector.ID == connectorID {
			delete(f.connectors, name)
		}
	}
	return nil
}

func (f *fakeMeshAPI) EnsureRoute(_ context.Context, connectorID, network, comment string) (*meshapi.Route, error) {
	for i := range f.routes {
		if f.routes[i].TunnelID == connectorID && f.routes[i].Network == network {
			return &f.routes[i], nil
		}
	}
	f.ensureRoutes++
	route := meshapi.Route{ID: fmt.Sprintf("route-%d", len(f.routes)+1), TunnelID: connectorID, Network: network, Comment: comment}
	f.routes = append(f.routes, route)
	return &f.routes[len(f.routes)-1], nil
}

func (f *fakeMeshAPI) ListRoutes(_ context.Context, _ string) ([]meshapi.Route, error) {
	return append([]meshapi.Route(nil), f.routes...), nil
}

func (f *fakeMeshAPI) DeleteRoute(_ context.Context, routeID string) error {
	f.deleted = append(f.deleted, routeID)
	for i := range f.routes {
		if f.routes[i].ID == routeID {
			f.routes = append(f.routes[:i], f.routes[i+1:]...)
			break
		}
	}
	return nil
}

func (f *fakeMeshAPI) ListDeviceRegistrations(_ context.Context) ([]meshapi.DeviceRegistration, error) {
	f.listedRegistrations++
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]meshapi.DeviceRegistration(nil), f.registrations...), nil
}

func (f *fakeMeshAPI) DeleteDeviceRegistration(_ context.Context, registrationID string) error {
	f.deletedRegistrations = append(f.deletedRegistrations, registrationID)
	for i := range f.registrations {
		if f.registrations[i].ID == registrationID {
			f.registrations = append(f.registrations[:i], f.registrations[i+1:]...)
			break
		}
	}
	return nil
}

func newRegistration(id, name, virtualIP string, age time.Duration, now time.Time) meshapi.DeviceRegistration {
	registration := meshapi.DeviceRegistration{ID: id, VirtualIPv4: virtualIP, CreatedAt: now.Add(-age)}
	registration.Device.Name = name
	return registration
}

// The node's own registration must survive; the one it abandoned must not; and
// anything without this cluster's prefix must never be touched, however old.
func TestReconcileCollectsOrphanedRegistrations(t *testing.T) {
	now := time.Now()
	kube, api := registrationGCFixture(t, now)
	op := newRegistrationGCOperator(t, kube, api, RegistrationGCOn, now)

	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	if want := []string{"reg-orphan"}; !reflect.DeepEqual(api.deletedRegistrations, want) {
		t.Fatalf("deleted registrations = %v, want %v", api.deletedRegistrations, want)
	}
	remaining := make([]string, 0, len(api.registrations))
	for i := range api.registrations {
		remaining = append(remaining, api.registrations[i].ID)
	}
	slices.Sort(remaining)
	if want := []string{"reg-fresh", "reg-live", "reg-unmanaged"}; !reflect.DeepEqual(remaining, want) {
		t.Fatalf("surviving registrations = %v, want %v", remaining, want)
	}
}

func TestRegistrationGCDryRunDeletesNothing(t *testing.T) {
	now := time.Now()
	kube, api := registrationGCFixture(t, now)
	op := newRegistrationGCOperator(t, kube, api, RegistrationGCDryRun, now)

	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(api.deletedRegistrations) != 0 {
		t.Fatalf("dry run deleted %v", api.deletedRegistrations)
	}
}

// Off must cost nothing: no listing either, so a cluster that does not want
// this feature never needs the extra API token permission.
func TestRegistrationGCOffSkipsTheListCall(t *testing.T) {
	now := time.Now()
	kube, api := registrationGCFixture(t, now)
	op := newRegistrationGCOperator(t, kube, api, RegistrationGCOff, now)

	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if api.listedRegistrations != 0 {
		t.Fatalf("listed registrations %d times while off", api.listedRegistrations)
	}
	if len(api.deletedRegistrations) != 0 {
		t.Fatalf("GC ran while off: %v", api.deletedRegistrations)
	}
}

// The Zero Trust scope is the only permission this loop needs beyond the
// connector ones, so a token that lacks it must degrade to "no GC" rather than
// wedge every reconcile.
func TestRegistrationGCFailureDoesNotFailReconcile(t *testing.T) {
	now := time.Now()
	kube, api := registrationGCFixture(t, now)
	api.listErr = errors.New("Cloudflare API HTTP 403: 10000: Authentication error")
	op := newRegistrationGCOperator(t, kube, api, RegistrationGCOn, now)

	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatalf("registration GC failure broke reconcile: %v", err)
	}
}

func TestNewRejectsUnknownRegistrationGCMode(t *testing.T) {
	_, err := New(fake.NewClientset(), &fakeMeshAPI{connectors: map[string]*meshapi.ConnectorCredentials{}}, Config{
		Namespace: "kube-flannel", SecretPrefix: "mesh-", ClusterName: "test", RegistrationGC: "sometimes",
	})
	if err == nil {
		t.Fatal("expected an unknown registration GC mode to be rejected")
	}
}

func registrationGCFixture(t *testing.T, now time.Time) (*fake.Clientset, *fakeMeshAPI) {
	t.Helper()
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-a",
			UID:  types.UID("uid-a"),
			Annotations: map[string]string{
				meshapi.DefaultAnnotationPrefix + "/backend-type": meshapi.BackendName,
				meshapi.DefaultAnnotationPrefix + "/backend-data": `{"connectorID":"id-flannel-test-node-a","meshIP":"100.96.0.8"}`,
			},
		},
		Spec: corev1.NodeSpec{PodCIDR: "10.10.1.0/24", PodCIDRs: []string{"10.10.1.0/24"}},
	}
	api := &fakeMeshAPI{
		connectors: map[string]*meshapi.ConnectorCredentials{},
		registrations: []meshapi.DeviceRegistration{
			newRegistration("reg-live", "flannel-test-node-a", "100.96.0.8", 24*time.Hour, now),
			newRegistration("reg-orphan", "flannel-test-node-a", "100.96.0.7", 24*time.Hour, now),
			newRegistration("reg-fresh", "flannel-test-node-b", "100.96.0.9", time.Minute, now),
			newRegistration("reg-unmanaged", "someones-laptop", "100.96.0.6", 90*24*time.Hour, now),
		},
	}
	return fake.NewClientset(node), api
}

func newRegistrationGCOperator(t *testing.T, kube *fake.Clientset, api *fakeMeshAPI, mode string, now time.Time) *Operator {
	t.Helper()
	op, err := New(kube, api, Config{
		Namespace: "kube-flannel", SecretPrefix: "mesh-", ClusterName: "test",
		ConnectorPrefix: "flannel-", SyncPeriod: time.Second, RegistrationGC: mode,
	})
	if err != nil {
		t.Fatal(err)
	}
	op.clock = func() time.Time { return now }
	return op
}

func TestReconcileBootstrapsNodeEnsuresRouteAndGarbageCollects(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-a",
			UID:  types.UID("uid-a"),
			Annotations: map[string]string{
				meshapi.DefaultAnnotationPrefix + "/backend-type": meshapi.BackendName,
				meshapi.DefaultAnnotationPrefix + "/backend-data": `{"connectorID":"id-flannel-test-node-a","meshIP":"100.96.0.8"}`,
			},
		},
		Spec: corev1.NodeSpec{PodCIDR: "10.10.1.0/24", PodCIDRs: []string{"10.10.1.0/24"}},
	}
	staleSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mesh-node-a",
			Namespace: "kube-flannel",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1", Kind: "Node", Name: "node-a", UID: types.UID("old-uid"),
			}},
		},
	}
	coreDNS := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "coredns", Namespace: "kube-system"},
		Data:       map[string]string{"NodeHosts": "192.0.2.10 existing-node\n"},
	}
	coreDNSDaemonSet := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "coredns", Namespace: "kube-system"}}
	kube := fake.NewClientset(node, staleSecret, coreDNS, coreDNSDaemonSet)
	api := &fakeMeshAPI{
		connectors: map[string]*meshapi.ConnectorCredentials{
			"flannel-test-old": {ID: "old", Name: "flannel-test-old", Token: "old-token"},
			"unmanaged":        {ID: "unmanaged", Name: "unmanaged", Token: "other-token"},
		},
		routes: []meshapi.Route{
			{ID: "stale", TunnelID: "old", Network: "10.10.9.0/24", Comment: "flannel:test:old:10.10.9.0/24"},
			{ID: "foreign", TunnelID: "other", Network: "192.0.2.0/24", Comment: "managed elsewhere"},
		},
	}
	op, err := New(kube, api, Config{
		Namespace: "kube-flannel", SecretPrefix: "mesh-", ClusterName: "test", ConnectorPrefix: "flannel-", SyncPeriod: time.Second,
		CoreDNSNodeHostsEnabled: true, CoreDNSNamespace: "kube-system", CoreDNSConfigMapName: "coredns", CoreDNSNodeHostsKey: "NodeHosts", CoreDNSHostnameSuffix: "-mesh", CoreDNSRolloutKind: "daemonset", CoreDNSRolloutName: "coredns",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	secret, err := kube.CoreV1().Secrets("kube-flannel").Get(context.Background(), "mesh-node-a", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(secret.Data[meshapi.SecretConnectorIDKey]); got != "id-flannel-test-node-a" {
		t.Fatalf("unexpected connector ID %q", got)
	}
	if len(secret.OwnerReferences) != 1 || secret.OwnerReferences[0].UID != node.UID {
		t.Fatalf("bootstrap Secret owner reference was not refreshed: %#v", secret.OwnerReferences)
	}
	if api.ensureRoutes != 1 {
		t.Fatalf("expected one new route, got %d", api.ensureRoutes)
	}
	if len(api.deleted) != 1 || api.deleted[0] != "stale" {
		t.Fatalf("unexpected deleted routes: %#v", api.deleted)
	}
	if len(api.deletedConnectors) != 1 || api.deletedConnectors[0] != "old" {
		t.Fatalf("unexpected deleted connectors: %#v", api.deletedConnectors)
	}
	updatedCoreDNS, err := kube.CoreV1().ConfigMaps("kube-system").Get(context.Background(), "coredns", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wantNodeHosts := "192.0.2.10 existing-node\n" +
		nodeHostsBeginMarker + "\n" +
		"100.96.0.8 node-a-mesh\n" +
		nodeHostsEndMarker + "\n"
	if got := updatedCoreDNS.Data["NodeHosts"]; got != wantNodeHosts {
		t.Fatalf("unexpected CoreDNS NodeHosts:\n%s", got)
	}
	updatedDaemonSet, err := kube.AppsV1().DaemonSets("kube-system").Get(context.Background(), "coredns", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if updatedDaemonSet.Spec.Template.Annotations[nodeHostsHashAnnotation] == "" {
		t.Fatal("CoreDNS DaemonSet did not receive the NodeHosts content hash")
	}

	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if api.ensureRoutes != 1 {
		t.Fatalf("second reconcile created another route")
	}
}

func TestMergeManagedNodeHostsReplacesOnlyManagedBlock(t *testing.T) {
	current := "192.0.2.10 existing-node\n" +
		nodeHostsBeginMarker + "\n" +
		"100.96.0.99 stale-mesh\n" +
		nodeHostsEndMarker + "\n"
	got, err := mergeManagedNodeHosts(current, map[string]string{
		"node-b-mesh": "100.96.0.9",
		"node-a-mesh": "100.96.0.8",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "192.0.2.10 existing-node\n" +
		nodeHostsBeginMarker + "\n" +
		"100.96.0.8 node-a-mesh\n" +
		"100.96.0.9 node-b-mesh\n" +
		nodeHostsEndMarker + "\n"
	if got != want {
		t.Fatalf("unexpected merged NodeHosts:\n%s", got)
	}
}

func TestMergeManagedNodeHostsRejectsMalformedBlock(t *testing.T) {
	if _, err := mergeManagedNodeHosts(nodeHostsBeginMarker+"\n100.96.0.8 node-a-mesh\n", nil); err == nil {
		t.Fatal("expected unmatched managed block marker to fail")
	}
}

func TestReconcileWaitsForFlannelLeaseBeforePublishingRoute(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-b", UID: types.UID("uid-b")}}
	kube := fake.NewClientset(node)
	api := &fakeMeshAPI{connectors: make(map[string]*meshapi.ConnectorCredentials)}
	op, err := New(kube, api, Config{
		Namespace: "kube-flannel", SecretPrefix: "mesh-", ClusterName: "test", ConnectorPrefix: "flannel-",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if api.ensureRoutes != 0 {
		t.Fatalf("route was published before the node acquired a Flannel lease")
	}
	if _, err := kube.CoreV1().Secrets("kube-flannel").Get(context.Background(), "mesh-node-b", metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, action := range kube.Actions() {
		if action.GetResource().Resource == "pods" {
			t.Fatalf("control-plane-only operator performed a Pod action: %s", action.GetVerb())
		}
	}
}
