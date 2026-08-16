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

// Registration garbage-collection modes. The default is deliberately dry-run:
// deleting registrations is destructive and account-wide, so an operator
// upgrade must not start reclaiming things before an admin has read the log
// and agreed with what it proposes.
const (
	RegistrationGCDryRun = "dryrun"
	RegistrationGCOn     = "on"
	RegistrationGCOff    = "off"
)

// registrationGCGrace is how long a registration is left alone after creation.
// flanneld enrols before it acquires a lease, so there is a window in which a
// perfectly healthy registration has not yet published its Mesh IP on the node.
const registrationGCGrace = 30 * time.Minute

// defaultRegistrationGCPeriod paces the sweep independently of SyncPeriod.
// Listing every registration on the account is far more expensive than the
// connector and route calls -- it is account-wide and paginated -- while an
// orphan costs nothing to leave in place for a few minutes, so there is no
// reason to pay for it on every reconcile.
const defaultRegistrationGCPeriod = 10 * time.Minute

type Config struct {
	Namespace               string
	SecretPrefix            string
	ClusterName             string
	ConnectorPrefix         string
	AnnotationPrefix        string
	NodeSelector            string
	SyncPeriod              time.Duration
	RegistrationGC          string
	RegistrationGCPeriod    time.Duration
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
	// nextRegistrationGC paces the sweep. Zero means "run on the next
	// reconcile", so a freshly elected leader sweeps once before settling into
	// the interval.
	nextRegistrationGC time.Time
	clock              func() time.Time
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
	if cfg.RegistrationGC == "" {
		cfg.RegistrationGC = RegistrationGCDryRun
	}
	if cfg.RegistrationGCPeriod <= 0 {
		cfg.RegistrationGCPeriod = defaultRegistrationGCPeriod
	}
	switch cfg.RegistrationGC {
	case RegistrationGCDryRun, RegistrationGCOn, RegistrationGCOff:
	default:
		return nil, fmt.Errorf("registration GC mode must be %s, %s, or %s, got %q",
			RegistrationGCDryRun, RegistrationGCOn, RegistrationGCOff, cfg.RegistrationGC)
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
	desiredMeshIPs := make(map[string]struct{})
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
		meshIP := net.ParseIP(data.MeshIP)
		if meshIP == nil || meshIP.To4() == nil {
			reconcileErrors = append(reconcileErrors, fmt.Errorf("node %s advertises invalid IPv4 Mesh IP %q", node.Name, data.MeshIP))
			continue
		}
		// Recorded for every node, not just when CoreDNS sync is on: this is
		// the set that tells registration GC which virtual IPs are live.
		desiredMeshIPs[meshIP.String()] = struct{}{}
		if o.cfg.CoreDNSNodeHostsEnabled {
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
	connectorPrefix := meshapi.ConnectorNamePrefix(o.cfg.ConnectorPrefix, o.cfg.ClusterName)
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
	// Reclaiming orphaned registrations is opportunistic: it frees virtual IPs
	// but never contributes to convergence, and it is the only part of this
	// loop that needs the Zero Trust token scope. A failure here -- a missing
	// permission being the likely one -- is logged rather than failing the
	// whole reconcile, so it cannot mask genuine errors every sync period.
	if err := o.collectRegistrations(ctx, desiredMeshIPs); err != nil {
		log.Errorf("cloudflare-mesh-operator: %v", err)
	}
	return errors.Join(reconcileErrors...)
}

// collectRegistrations reclaims WARP registrations abandoned by nodes that
// re-enrolled without deleting their predecessor -- typically because the
// per-node state file was lost, which leaves flanneld with no record to delete.
// Each orphan holds a Mesh virtual IP, and Cloudflare never reclaims them.
//
// It is deliberately conservative: only registrations carrying this cluster's
// connector-name prefix are ever considered, so an unrelated user device can
// never be matched, and nothing is deleted until it has had
// registrationGCGrace to publish its Mesh IP on the node object.
func (o *Operator) collectRegistrations(ctx context.Context, desiredMeshIPs map[string]struct{}) error {
	if o.cfg.RegistrationGC == RegistrationGCOff {
		return nil
	}
	now := o.now()
	if now.Before(o.nextRegistrationGC) {
		return nil
	}
	// Scheduled before the work, not after, so a failing sweep -- a missing
	// token scope being the likely one -- backs off instead of retrying and
	// logging on every reconcile.
	o.nextRegistrationGC = now.Add(o.cfg.RegistrationGCPeriod)

	registrations, err := o.api.ListDeviceRegistrations(ctx)
	if err != nil {
		return fmt.Errorf("list device registrations for garbage collection: %w", err)
	}
	prefix := meshapi.ConnectorNamePrefix(o.cfg.ConnectorPrefix, o.cfg.ClusterName)
	cutoff := now.Add(-registrationGCGrace)
	var errs []error
	for i := range registrations {
		registration := &registrations[i]
		if !strings.HasPrefix(registration.Name(), prefix) {
			continue
		}
		if _, ok := desiredMeshIPs[registration.VirtualIPv4]; ok {
			continue
		}
		if registration.CreatedAt.After(cutoff) {
			log.Infof("cloudflare-mesh-operator: registration %s (%s, %s) is unclaimed but younger than %s; leaving it",
				registration.ID, registration.Name(), registration.VirtualIPv4, registrationGCGrace)
			continue
		}
		if o.cfg.RegistrationGC == RegistrationGCDryRun {
			log.Infof("cloudflare-mesh-operator: would delete orphaned registration %s (%s, %s, created %s)",
				registration.ID, registration.Name(), registration.VirtualIPv4, registration.CreatedAt.Format(time.RFC3339))
			continue
		}
		if err := o.api.DeleteDeviceRegistration(ctx, registration.ID); err != nil {
			errs = append(errs, fmt.Errorf("delete orphaned registration %s: %w", registration.ID, err))
			continue
		}
		log.Infof("cloudflare-mesh-operator: deleted orphaned registration %s (%s, %s)",
			registration.ID, registration.Name(), registration.VirtualIPv4)
	}
	return errors.Join(errs...)
}

func (o *Operator) now() time.Time {
	if o.clock != nil {
		return o.clock()
	}
	return time.Now()
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
