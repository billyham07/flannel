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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path"
	"reflect"
	"strconv"
	"strings"
	"time"

	meshapi "github.com/flannel-io/flannel/pkg/cloudflaremesh"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
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
	MeshPodEnabled          bool
	MeshPodImage            string
	MeshPodPullPolicy       corev1.PullPolicy
	MeshPodNamePrefix       string
	MeshStateHostPath       string
	MeshSRCNATEnabled       bool
	MeshPodMemoryRequest    string
	MeshPodMemoryLimit      string
	MeshPodMemoryRestartAt  string
	MeshPodMemoryCheckEvery time.Duration
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
	if cfg.MeshPodEnabled {
		if cfg.MeshPodImage == "" {
			return nil, errors.New("Mesh Pod image is required when Mesh Pod management is enabled")
		}
		if cfg.MeshPodPullPolicy == "" {
			cfg.MeshPodPullPolicy = corev1.PullIfNotPresent
		}
		if cfg.MeshPodNamePrefix == "" {
			cfg.MeshPodNamePrefix = cfg.SecretPrefix
		}
		if cfg.MeshStateHostPath == "" {
			cfg.MeshStateHostPath = "/var/lib/cloudflare-mesh"
		}
		if cfg.MeshPodMemoryRequest == "" {
			cfg.MeshPodMemoryRequest = "64Mi"
		}
		if cfg.MeshPodMemoryLimit == "" {
			cfg.MeshPodMemoryLimit = "200Mi"
		}
		if cfg.MeshPodMemoryRestartAt == "" {
			cfg.MeshPodMemoryRestartAt = "160Mi"
		}
		if cfg.MeshPodMemoryCheckEvery <= 0 {
			cfg.MeshPodMemoryCheckEvery = time.Minute
		}
		request, err := resource.ParseQuantity(cfg.MeshPodMemoryRequest)
		if err != nil || request.Sign() <= 0 {
			return nil, fmt.Errorf("invalid Mesh Pod memory request %q", cfg.MeshPodMemoryRequest)
		}
		limit, err := resource.ParseQuantity(cfg.MeshPodMemoryLimit)
		if err != nil || limit.Sign() <= 0 {
			return nil, fmt.Errorf("invalid Mesh Pod memory limit %q", cfg.MeshPodMemoryLimit)
		}
		restartAt, err := resource.ParseQuantity(cfg.MeshPodMemoryRestartAt)
		if err != nil || restartAt.Sign() <= 0 {
			return nil, fmt.Errorf("invalid Mesh Pod memory restart threshold %q", cfg.MeshPodMemoryRestartAt)
		}
		if request.Cmp(limit) > 0 {
			return nil, fmt.Errorf("Mesh Pod memory request %s exceeds limit %s", request.String(), limit.String())
		}
		if restartAt.Cmp(limit) >= 0 {
			return nil, fmt.Errorf("Mesh Pod memory restart threshold %s must be below limit %s", restartAt.String(), limit.String())
		}
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
	desiredPods := make(map[string]struct{})
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
		if o.cfg.MeshPodEnabled {
			podName := meshapi.NodePodName(o.cfg.MeshPodNamePrefix, node.Name)
			desiredPods[podName] = struct{}{}
			if err := o.ensureMeshPod(ctx, node, connector, len(nodes.Items)); err != nil {
				reconcileErrors = append(reconcileErrors, err)
				continue
			}
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
	if o.cfg.MeshPodEnabled {
		selector := meshapi.ManagedByLabel + "=" + meshapi.ManagedByOperator + "," +
			meshapi.MeshPodComponentLabel + "=" + meshapi.MeshPodComponent
		pods, err := o.kube.CoreV1().Pods(o.cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			return fmt.Errorf("list managed Mesh Pods: %w", err)
		}
		for i := range pods.Items {
			pod := &pods.Items[i]
			if _, ok := desiredPods[pod.Name]; ok {
				continue
			}
			if err := o.kube.CoreV1().Pods(o.cfg.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				reconcileErrors = append(reconcileErrors, fmt.Errorf("delete stale Mesh Pod %s/%s: %w", pod.Namespace, pod.Name, err))
			}
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

func (o *Operator) ensureMeshPod(ctx context.Context, node *corev1.Node, connector *meshapi.ConnectorCredentials, desiredPodCount int) error {
	podName := meshapi.NodePodName(o.cfg.MeshPodNamePrefix, node.Name)
	secretName := meshapi.NodeSecretName(o.cfg.SecretPrefix, node.Name)
	statePath := path.Join(o.cfg.MeshStateHostPath, meshapi.ConnectorStateDirectory(connector.ID))
	owner := metav1.OwnerReference{APIVersion: "v1", Kind: "Node", Name: node.Name, UID: node.UID}
	revision := meshPodRevision(o.cfg, node.Name, connector.ID, secretName, statePath)
	automount := false
	allowPrivilegeEscalation := false
	runAsUser := int64(0)
	directoryOrCreate := corev1.HostPathDirectoryOrCreate
	charDevice := corev1.HostPathCharDev
	memoryRequest := resource.MustParse(o.cfg.MeshPodMemoryRequest)
	memoryLimit := resource.MustParse(o.cfg.MeshPodMemoryLimit)
	memoryRestartAt := resource.MustParse(o.cfg.MeshPodMemoryRestartAt)
	memoryCheckSeconds := int32(o.cfg.MeshPodMemoryCheckEvery / time.Second)
	if memoryCheckSeconds < 1 {
		memoryCheckSeconds = 1
	}
	desiredLabels := map[string]string{
		meshapi.ManagedByLabel:        meshapi.ManagedByOperator,
		meshapi.MeshPodComponentLabel: meshapi.MeshPodComponent,
		"app.kubernetes.io/name":      "cloudflare-mesh",
	}
	desired := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            podName,
			Namespace:       o.cfg.Namespace,
			Labels:          desiredLabels,
			Annotations:     map[string]string{meshapi.ConnectorIDAnnotation: connector.ID, "cloudflare-mesh.flannel.io/revision": revision},
			OwnerReferences: []metav1.OwnerReference{owner},
		},
		Spec: corev1.PodSpec{
			NodeName:                     node.Name,
			HostNetwork:                  true,
			DNSPolicy:                    corev1.DNSClusterFirstWithHostNet,
			PriorityClassName:            "system-node-critical",
			RestartPolicy:                corev1.RestartPolicyAlways,
			AutomountServiceAccountToken: &automount,
			EnableServiceLinks:           &automount,
			Tolerations: []corev1.Toleration{
				{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
				{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
			},
			Containers: []corev1.Container{{
				Name:            "mesh",
				Image:           o.cfg.MeshPodImage,
				ImagePullPolicy: o.cfg.MeshPodPullPolicy,
				Env: []corev1.EnvVar{
					{Name: "MESH_NODE_TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: secretName}, Key: meshapi.SecretConnectorTokenKey}}},
					{Name: "SRCNAT_ENABLED", Value: strconv.FormatBool(o.cfg.MeshSRCNATEnabled)},
				},
				SecurityContext: &corev1.SecurityContext{
					RunAsUser:                &runAsUser,
					AllowPrivilegeEscalation: &allowPrivilegeEscalation,
					Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN", "NET_RAW"}},
				},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceMemory: memoryRequest},
					Limits:   corev1.ResourceList{corev1.ResourceMemory: memoryLimit},
				},
				LivenessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{
						"sh", "-c", fmt.Sprintf("usage=$(cat /sys/fs/cgroup/memory.current 2>/dev/null || cat /sys/fs/cgroup/memory/memory.usage_in_bytes 2>/dev/null || true); [ -z \"$usage\" ] || [ \"$usage\" -lt %d ]", memoryRestartAt.Value()),
					}}},
					InitialDelaySeconds: 300,
					PeriodSeconds:       memoryCheckSeconds,
					TimeoutSeconds:      5,
					FailureThreshold:    1,
				},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "warp-data", MountPath: "/var/lib/cloudflare-warp"},
					{Name: "dev-net-tun", MountPath: "/dev/net/tun"},
					{Name: "run-dbus", MountPath: "/run/dbus"},
				},
			}},
			Volumes: []corev1.Volume{
				{Name: "warp-data", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: statePath, Type: &directoryOrCreate}}},
				{Name: "dev-net-tun", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/dev/net/tun", Type: &charDevice}}},
				{Name: "run-dbus", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}},
			},
		},
	}

	pods := o.kube.CoreV1().Pods(o.cfg.Namespace)
	existing, err := pods.Get(ctx, podName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = pods.Create(ctx, desired, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("create Mesh Pod for node %s: %w", node.Name, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get Mesh Pod for node %s: %w", node.Name, err)
	}
	if existing.DeletionTimestamp != nil {
		return nil
	}
	if existing.Annotations["cloudflare-mesh.flannel.io/revision"] != revision {
		replacementInProgress, err := o.meshPodReplacementInProgress(ctx, podName, desiredPodCount)
		if err != nil {
			return err
		}
		if replacementInProgress {
			return nil
		}
		if err := pods.Delete(ctx, podName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("replace Mesh Pod for node %s: %w", node.Name, err)
		}
		return nil
	}
	if reflect.DeepEqual(existing.Labels, desiredLabels) && reflect.DeepEqual(existing.OwnerReferences, []metav1.OwnerReference{owner}) {
		return nil
	}
	existing.Labels = desiredLabels
	existing.OwnerReferences = []metav1.OwnerReference{owner}
	if existing.Annotations == nil {
		existing.Annotations = make(map[string]string)
	}
	existing.Annotations[meshapi.ConnectorIDAnnotation] = connector.ID
	_, err = pods.Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

func (o *Operator) meshPodReplacementInProgress(ctx context.Context, currentPod string, desiredPodCount int) (bool, error) {
	selector := meshapi.ManagedByLabel + "=" + meshapi.ManagedByOperator + "," +
		meshapi.MeshPodComponentLabel + "=" + meshapi.MeshPodComponent
	pods, err := o.kube.CoreV1().Pods(o.cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return false, fmt.Errorf("list Mesh Pods before replacing %s: %w", currentPod, err)
	}
	if len(pods.Items) < desiredPodCount {
		return true, nil
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Name == currentPod {
			continue
		}
		if pod.DeletionTimestamp != nil || !meshPodReady(pod) {
			return true, nil
		}
	}
	return false, nil
}

func meshPodReady(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning {
		return false
	}
	for i := range pod.Status.ContainerStatuses {
		if pod.Status.ContainerStatuses[i].Name == "mesh" {
			return pod.Status.ContainerStatuses[i].Ready
		}
	}
	return false
}

func meshPodRevision(cfg Config, nodeName, connectorID, secretName, statePath string) string {
	data, _ := json.Marshal(struct {
		NodeName         string
		ConnectorID      string
		SecretName       string
		StatePath        string
		Image            string
		PullPolicy       corev1.PullPolicy
		SRCNAT           bool
		MemoryRequest    string
		MemoryLimit      string
		MemoryRestartAt  string
		MemoryCheckEvery time.Duration
	}{nodeName, connectorID, secretName, statePath, cfg.MeshPodImage, cfg.MeshPodPullPolicy, cfg.MeshSRCNATEnabled, cfg.MeshPodMemoryRequest, cfg.MeshPodMemoryLimit, cfg.MeshPodMemoryRestartAt, cfg.MeshPodMemoryCheckEvery})
	return fmt.Sprintf("%x", sha256.Sum256(data))
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
