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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	meshapi "github.com/flannel-io/flannel/pkg/cloudflaremesh"
	meshoperator "github.com/flannel-io/flannel/pkg/cloudflaremeshoperator"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	log "k8s.io/klog/v2"
)

type options struct {
	accountID               string
	apiTokenFile            string
	apiBaseURL              string
	kubeconfig              string
	namespace               string
	secretPrefix            string
	clusterName             string
	connectorPrefix         string
	annotationPrefix        string
	nodeSelector            string
	syncPeriod              time.Duration
	connectorHA             bool
	meshPodEnabled          bool
	meshPodImage            string
	meshPodPullPolicy       string
	meshPodNamePrefix       string
	meshStateHostPath       string
	meshSRCNATEnabled       bool
	coreDNSNodeHostsEnabled bool
	coreDNSNamespace        string
	coreDNSConfigMapName    string
	coreDNSNodeHostsKey     string
	coreDNSHostnameSuffix   string
	leaderElect             bool
	leaseName               string
	leaseNamespace          string
}

func main() {
	log.InitFlags(nil)
	opts := parseFlags()
	flag.Parse()
	defer log.Flush()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *opts); err != nil {
		log.Fatalf("cloudflare-mesh-operator: %v", err)
	}
}

func parseFlags() *options {
	opts := &options{}
	flag.StringVar(&opts.accountID, "cloudflare-account-id", os.Getenv("CLOUDFLARE_ACCOUNT_ID"), "Cloudflare account ID")
	flag.StringVar(&opts.apiTokenFile, "cloudflare-api-token-file", "/var/run/secrets/cloudflare-mesh/api-token", "Cloudflare API token file")
	flag.StringVar(&opts.apiBaseURL, "cloudflare-api-base-url", "https://api.cloudflare.com/client/v4", "Cloudflare API base URL")
	flag.StringVar(&opts.kubeconfig, "kubeconfig", "", "Path to kubeconfig; empty uses in-cluster configuration")
	flag.StringVar(&opts.namespace, "namespace", "kube-flannel", "Namespace for bootstrap Secrets")
	flag.StringVar(&opts.secretPrefix, "secret-prefix", "cloudflare-mesh-node-", "Per-node bootstrap Secret prefix")
	flag.StringVar(&opts.clusterName, "cluster-name", "default", "Stable cluster name used for Cloudflare resource ownership")
	flag.StringVar(&opts.connectorPrefix, "connector-prefix", "flannel-", "Cloudflare Mesh node name prefix")
	flag.StringVar(&opts.annotationPrefix, "annotation-prefix", meshapi.DefaultAnnotationPrefix, "Flannel Node annotation prefix")
	flag.StringVar(&opts.nodeSelector, "node-selector", "", "Kubernetes label selector for managed nodes")
	flag.DurationVar(&opts.syncPeriod, "sync-period", 15*time.Second, "Full reconciliation period")
	flag.BoolVar(&opts.connectorHA, "connector-ha", false, "Create Cloudflare Mesh nodes with HA enabled")
	flag.BoolVar(&opts.meshPodEnabled, "mesh-pod-enabled", false, "Manage one containerized Cloudflare Mesh Pod per node")
	flag.StringVar(&opts.meshPodImage, "mesh-pod-image", "cloudflare/mesh:latest", "Container image for per-node Cloudflare Mesh Pods")
	flag.StringVar(&opts.meshPodPullPolicy, "mesh-pod-image-pull-policy", string(corev1.PullIfNotPresent), "Image pull policy for Cloudflare Mesh Pods")
	flag.StringVar(&opts.meshPodNamePrefix, "mesh-pod-name-prefix", "cloudflare-mesh-node-", "Per-node Cloudflare Mesh Pod name prefix")
	flag.StringVar(&opts.meshStateHostPath, "mesh-state-host-path", "/var/lib/cloudflare-mesh", "Host path root for per-connector Cloudflare Mesh registration state")
	flag.BoolVar(&opts.meshSRCNATEnabled, "mesh-srcnat-enabled", false, "Enable source NAT in containerized Cloudflare Mesh nodes")
	flag.BoolVar(&opts.coreDNSNodeHostsEnabled, "coredns-node-hosts-enabled", false, "Publish Node Mesh IP hostnames to a CoreDNS NodeHosts ConfigMap")
	flag.StringVar(&opts.coreDNSNamespace, "coredns-namespace", "kube-system", "Namespace containing the CoreDNS NodeHosts ConfigMap")
	flag.StringVar(&opts.coreDNSConfigMapName, "coredns-configmap-name", "coredns", "CoreDNS NodeHosts ConfigMap name")
	flag.StringVar(&opts.coreDNSNodeHostsKey, "coredns-node-hosts-key", "NodeHosts", "Data key containing the CoreDNS hosts file")
	flag.StringVar(&opts.coreDNSHostnameSuffix, "coredns-hostname-suffix", "-mesh", "Suffix appended to Kubernetes Node names in CoreDNS")
	flag.BoolVar(&opts.leaderElect, "leader-elect", true, "Enable Kubernetes Lease leader election")
	flag.StringVar(&opts.leaseName, "leader-election-lease", "cloudflare-mesh-operator", "Leader election Lease name")
	flag.StringVar(&opts.leaseNamespace, "leader-election-namespace", "kube-flannel", "Leader election Lease namespace")
	return opts
}

func run(ctx context.Context, opts options) error {
	if opts.accountID == "" {
		return fmt.Errorf("--cloudflare-account-id is required")
	}
	tokenBytes, err := os.ReadFile(opts.apiTokenFile)
	if err != nil {
		return fmt.Errorf("read Cloudflare API token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return fmt.Errorf("Cloudflare API token is empty")
	}

	restConfig, err := kubernetesConfig(opts.kubeconfig)
	if err != nil {
		return err
	}
	kube, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("create Kubernetes client: %w", err)
	}
	api, err := meshapi.NewClient(opts.apiBaseURL, opts.accountID, token, nil)
	if err != nil {
		return err
	}
	pullPolicy := corev1.PullPolicy(opts.meshPodPullPolicy)
	if pullPolicy != corev1.PullAlways && pullPolicy != corev1.PullIfNotPresent && pullPolicy != corev1.PullNever {
		return fmt.Errorf("invalid --mesh-pod-image-pull-policy %q", opts.meshPodPullPolicy)
	}
	operator, err := meshoperator.New(kube, api, meshoperator.Config{
		Namespace:               opts.namespace,
		SecretPrefix:            opts.secretPrefix,
		ClusterName:             opts.clusterName,
		ConnectorPrefix:         opts.connectorPrefix,
		AnnotationPrefix:        opts.annotationPrefix,
		NodeSelector:            opts.nodeSelector,
		SyncPeriod:              opts.syncPeriod,
		ConnectorHA:             opts.connectorHA,
		MeshPodEnabled:          opts.meshPodEnabled,
		MeshPodImage:            opts.meshPodImage,
		MeshPodPullPolicy:       pullPolicy,
		MeshPodNamePrefix:       opts.meshPodNamePrefix,
		MeshStateHostPath:       opts.meshStateHostPath,
		MeshSRCNATEnabled:       opts.meshSRCNATEnabled,
		CoreDNSNodeHostsEnabled: opts.coreDNSNodeHostsEnabled,
		CoreDNSNamespace:        opts.coreDNSNamespace,
		CoreDNSConfigMapName:    opts.coreDNSConfigMapName,
		CoreDNSNodeHostsKey:     opts.coreDNSNodeHostsKey,
		CoreDNSHostnameSuffix:   opts.coreDNSHostnameSuffix,
	})
	if err != nil {
		return err
	}
	if !opts.leaderElect {
		operator.Run(ctx)
		return nil
	}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{Name: opts.leaseName, Namespace: opts.leaseNamespace},
		Client:    kube.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: hostname + "_" + string(uuid.NewUUID()),
		},
	}
	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		LeaseDuration:   30 * time.Second,
		RenewDeadline:   20 * time.Second,
		RetryPeriod:     5 * time.Second,
		ReleaseOnCancel: true,
		Name:            "cloudflare-mesh-operator",
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: operator.Run,
			OnStoppedLeading: func() { log.Info("cloudflare-mesh-operator: leadership lost") },
		},
	})
	return nil
}

func kubernetesConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("load kubeconfig: %w", err)
		}
		return cfg, nil
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster config: %w", err)
	}
	return cfg, nil
}
