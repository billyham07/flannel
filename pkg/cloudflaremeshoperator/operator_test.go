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
	"fmt"
	"strings"
	"testing"
	"time"

	meshapi "github.com/flannel-io/flannel/pkg/cloudflaremesh"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

type fakeMeshAPI struct {
	connectors        map[string]*meshapi.ConnectorCredentials
	routes            []meshapi.Route
	ensureRoutes      int
	deleted           []string
	deletedConnectors []string
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
	kube := fake.NewClientset(node, staleSecret)
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

	if err := op.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if api.ensureRoutes != 1 {
		t.Fatalf("second reconcile created another route")
	}
}

func TestReconcileWaitsForFlannelLeaseBeforePublishingRoute(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-b", UID: types.UID("uid-b")}}
	kube := fake.NewClientset(node)
	api := &fakeMeshAPI{connectors: make(map[string]*meshapi.ConnectorCredentials)}
	op, err := New(kube, api, Config{
		Namespace: "kube-flannel", SecretPrefix: "mesh-", ClusterName: "test", ConnectorPrefix: "flannel-",
		MeshPodEnabled: true, MeshPodImage: "cloudflare/mesh:test", MeshStateHostPath: "/var/lib/test-mesh",
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
	pod, err := kube.CoreV1().Pods("kube-flannel").Get(context.Background(), "mesh-node-b", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !pod.Spec.HostNetwork || pod.Spec.NodeName != "node-b" {
		t.Fatalf("Mesh Pod is not pinned to the host network on node-b: %#v", pod.Spec)
	}
	if got := pod.Spec.Containers[0].Image; got != "cloudflare/mesh:test" {
		t.Fatalf("unexpected Mesh Pod image %q", got)
	}
	if got := pod.Spec.Containers[0].Env[0].ValueFrom.SecretKeyRef.Name; got != "mesh-node-b" {
		t.Fatalf("Mesh Pod uses unexpected token Secret %q", got)
	}
	if got := pod.Spec.Volumes[0].HostPath.Path; !strings.HasPrefix(got, "/var/lib/test-mesh/connector-") {
		t.Fatalf("unexpected Mesh state host path %q", got)
	}
}
