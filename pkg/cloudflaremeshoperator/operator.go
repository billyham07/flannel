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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

	meshapi "github.com/flannel-io/flannel/pkg/cloudflaremesh"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	log "k8s.io/klog/v2"
)

type Config struct {
	Namespace               string
	SecretPrefix            string
	ClusterName             string
	ConnectorPrefix         string
	AnnotationPrefix        string
	NodeSelector            string
	SyncPeriod              time.Duration
	ConnectorHA             bool
	CoreDNSNodeHostsEnabled bool
	CoreDNSNamespace        string
	CoreDNSConfigMapName    string
	CoreDNSNodeHostsKey     string
	CoreDNSHostnameSuffix   string
	CoreDNSRolloutKind      string
	CoreDNSRolloutName      string
}

type Operator struct {
	kube kubernetes.Interface
	api  meshapi.API
	cfg  Config
}

func New(kube kubernetes.Interface, api meshapi.API, cfg Config) (*Operator, error) {
	if kube == nil || api == nil {
		return nil, errors.New("Kubernetes and Cloudflare API clients are required")
	}
	if cfg.Namespace == "" || cfg.SecretPrefix == "" || cfg.ClusterName == "" {
		return nil, errors.New("operator namespace, Secret prefix, and cluster name are required")
	}
	if cfg.AnnotationPrefix == "" {
		cfg.AnnotationPrefix = meshapi.DefaultAnnotationPrefix
	}
	if cfg.SyncPeriod <= 0 {
		cfg.SyncPeriod = 15 * time.Second
	}
	if cfg.CoreDNSNodeHostsEnabled {
		if cfg.CoreDNSNamespace == "" || cfg.CoreDNSConfigMapName == "" || cfg.CoreDNSNodeHostsKey == "" || cfg.CoreDNSRolloutName == "" {
			return nil, errors.New("CoreDNS namespace, ConfigMap name, NodeHosts key, and rollout workload name are required when NodeHosts sync is enabled")
		}
		if cfg.CoreDNSHostnameSuffix == "" {
			cfg.CoreDNSHostnameSuffix = "-mesh"
		}
		cfg.CoreDNSRolloutKind = strings.ToLower(cfg.CoreDNSRolloutKind)
		if cfg.CoreDNSRolloutKind != "deployment" && cfg.CoreDNSRolloutKind != "daemonset" {
			return nil, fmt.Errorf("CoreDNS rollout kind must be deployment or daemonset, got %q", cfg.CoreDNSRolloutKind)
		}
	}
	return &Operator{kube: kube, api: api, cfg: cfg}, nil
}

func (o *Operator) Run(ctx context.Context) {
	o.reconcileAndLog(ctx)
	ticker := time.NewTicker(o.cfg.SyncPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.reconcileAndLog(ctx)
		}
	}
}

func (o *Operator) Reconcile(ctx context.Context) error {
	nodes, err := o.kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: o.cfg.NodeSelector})
	if err != nil {
		return fmt.Errorf("list Kubernetes nodes: %w", err)
	}

	desiredRoutes := make(map[string]struct{})
	desiredConnectors := make(map[string]struct{})
	desiredNodeHosts := make(map[string]string)
	var reconcileErrors []error
	for i := range nodes.Items {
		node := &nodes.Items[i]
		connectorName := meshapi.ConnectorName(o.cfg.ConnectorPrefix, o.cfg.ClusterName, node.Name)
		connector, err := o.api.EnsureConnector(ctx, "", connectorName, o.cfg.ConnectorHA)
		if err != nil {
			reconcileErrors = append(reconcileErrors, fmt.Errorf("ensure connector for node %s: %w", node.Name, err))
			continue
		}
		desiredConnectors[connector.ID] = struct{}{}
		if err := o.ensureBootstrapSecret(ctx, node, connector); err != nil {
			reconcileErrors = append(reconcileErrors, err)
			continue
		}

		backendType := node.Annotations[o.cfg.AnnotationPrefix+"/backend-type"]
		if backendType != meshapi.BackendName {
			continue
		}
		data, err := parseLeaseData(node.Annotations[o.cfg.AnnotationPrefix+"/backend-data"])
		if err != nil {
			reconcileErrors = append(reconcileErrors, fmt.Errorf("parse backend data for node %s: %w", node.Name, err))
			continue
		}
		if data.ConnectorID != connector.ID {
			reconcileErrors = append(reconcileErrors, fmt.Errorf("node %s advertises connector %s, operator owns %s", node.Name, data.ConnectorID, connector.ID))
			continue
		}
		if o.cfg.CoreDNSNodeHostsEnabled {
			meshIP := net.ParseIP(data.MeshIP)
			if meshIP == nil || meshIP.To4() == nil {
				reconcileErrors = append(reconcileErrors, fmt.Errorf("node %s advertises invalid IPv4 Mesh IP %q", node.Name, data.MeshIP))
				continue
			}
			desiredNodeHosts[node.Name+o.cfg.CoreDNSHostnameSuffix] = meshIP.String()
		}
		network, err := nodeIPv4PodCIDR(node)
		if err != nil {
			reconcileErrors = append(reconcileErrors, err)
			continue
		}
		comment := meshapi.RouteComment(o.cfg.ClusterName, node.Name, network)
		route, err := o.api.EnsureRoute(ctx, connector.ID, network, comment)
		if err != nil {
			reconcileErrors = append(reconcileErrors, fmt.Errorf("ensure route for node %s: %w", node.Name, err))
			continue
		}
		desiredRoutes[routeKey(route.TunnelID, route.Network)] = struct{}{}
	}
	if len(reconcileErrors) == 0 && o.cfg.CoreDNSNodeHostsEnabled {
		nodeHosts, err := o.ensureCoreDNSNodeHosts(ctx, desiredNodeHosts)
		if err != nil {
			reconcileErrors = append(reconcileErrors, err)
		} else if err := o.ensureCoreDNSReload(ctx, nodeHosts); err != nil {
			reconcileErrors = append(reconcileErrors, err)
		}
	}
	if len(reconcileErrors) > 0 {
		return errors.Join(reconcileErrors...)
	}

	routes, err := o.api.ListRoutes(ctx, "")
	if err != nil {
		return fmt.Errorf("list routes for garbage collection: %w", err)
	}
	commentPrefix := meshapi.RouteCommentPrefix(o.cfg.ClusterName)
	for i := range routes {
		route := &routes[i]
		if !strings.HasPrefix(route.Comment, commentPrefix) {
			continue
		}
		if _, ok := desiredRoutes[routeKey(route.TunnelID, route.Network)]; ok {
			continue
		}
		if err := o.api.DeleteRoute(ctx, route.ID); err != nil {
			reconcileErrors = append(reconcileErrors, err)
		}
	}
	if len(reconcileErrors) > 0 {
		return errors.Join(reconcileErrors...)
	}

	connectors, err := o.api.ListConnectors(ctx)
	if err != nil {
		return fmt.Errorf("list connectors for garbage collection: %w", err)
	}
	connectorPrefix := o.cfg.ConnectorPrefix + o.cfg.ClusterName + "-"
	for i := range connectors {
		connector := &connectors[i]
		if !strings.HasPrefix(connector.Name, connectorPrefix) {
			continue
		}
		if _, ok := desiredConnectors[connector.ID]; ok {
			continue
		}
		if err := o.api.DeleteConnector(ctx, connector.ID); err != nil {
			reconcileErrors = append(reconcileErrors, err)
		}
	}
	return errors.Join(reconcileErrors...)
}

func (o *Operator) reconcileAndLog(ctx context.Context) {
	if err := o.Reconcile(ctx); err != nil {
		log.Errorf("cloudflare-mesh-operator: reconcile failed: %v", err)
	}
}

func (o *Operator) ensureBootstrapSecret(ctx context.Context, node *corev1.Node, connector *meshapi.ConnectorCredentials) error {
	name := meshapi.NodeSecretName(o.cfg.SecretPrefix, node.Name)
	desiredData := map[string][]byte{
		meshapi.SecretConnectorIDKey:    []byte(connector.ID),
		meshapi.SecretConnectorNameKey:  []byte(connector.Name),
		meshapi.SecretConnectorTokenKey: []byte(connector.Token),
	}
	owner := metav1.OwnerReference{
		APIVersion: "v1",
		Kind:       "Node",
		Name:       node.Name,
		UID:        node.UID,
	}
	secrets := o.kube.CoreV1().Secrets(o.cfg.Namespace)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		secret, err := secrets.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err = secrets.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            name,
					Namespace:       o.cfg.Namespace,
					Labels:          map[string]string{meshapi.ManagedByLabel: meshapi.ManagedByOperator},
					OwnerReferences: []metav1.OwnerReference{owner},
				},
				Type: corev1.SecretTypeOpaque,
				Data: desiredData,
			}, metav1.CreateOptions{})
			return err
		}
		if err != nil {
			return err
		}
		if reflect.DeepEqual(secret.Data, desiredData) &&
			secret.Labels[meshapi.ManagedByLabel] == meshapi.ManagedByOperator &&
			reflect.DeepEqual(secret.OwnerReferences, []metav1.OwnerReference{owner}) {
			return nil
		}
		secret.Data = desiredData
		secret.OwnerReferences = []metav1.OwnerReference{owner}
		if secret.Labels == nil {
			secret.Labels = make(map[string]string)
		}
		secret.Labels[meshapi.ManagedByLabel] = meshapi.ManagedByOperator
		_, err = secrets.Update(ctx, secret, metav1.UpdateOptions{})
		return err
	})
}

func parseLeaseData(raw string) (*meshapi.LeaseData, error) {
	if raw == "" {
		return nil, errors.New("backend-data annotation is empty")
	}
	var data meshapi.LeaseData
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil, err
	}
	if data.ConnectorID == "" {
		return nil, errors.New("backend-data has no connectorID")
	}
	return &data, nil
}

func nodeIPv4PodCIDR(node *corev1.Node) (string, error) {
	cidrs := append([]string(nil), node.Spec.PodCIDRs...)
	if len(cidrs) == 0 && node.Spec.PodCIDR != "" {
		cidrs = append(cidrs, node.Spec.PodCIDR)
	}
	for _, cidr := range cidrs {
		ipAddress, network, err := net.ParseCIDR(cidr)
		if err == nil && ipAddress.To4() != nil {
			return network.String(), nil
		}
	}
	return "", fmt.Errorf("node %s has no IPv4 PodCIDR", node.Name)
}

func routeKey(connectorID, network string) string {
	return connectorID + "\x00" + network
}
