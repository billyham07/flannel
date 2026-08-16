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
	"errors"
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

const (
	nodeHostsBeginMarker    = "# BEGIN cloudflare-mesh-operator"
	nodeHostsEndMarker      = "# END cloudflare-mesh-operator"
	nodeHostsHashAnnotation = "cloudflare-mesh.flannel.io/node-hosts-hash"
)

func (o *Operator) ensureCoreDNSNodeHosts(ctx context.Context, desiredHosts map[string]string) (string, error) {
	configMaps := o.kube.CoreV1().ConfigMaps(o.cfg.CoreDNSNamespace)
	var rendered string
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		configMap, err := configMaps.Get(ctx, o.cfg.CoreDNSConfigMapName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get CoreDNS NodeHosts ConfigMap %s/%s: %w", o.cfg.CoreDNSNamespace, o.cfg.CoreDNSConfigMapName, err)
		}
		current := configMap.Data[o.cfg.CoreDNSNodeHostsKey]
		desired, err := mergeManagedNodeHosts(current, desiredHosts)
		if err != nil {
			return fmt.Errorf("merge CoreDNS NodeHosts: %w", err)
		}
		rendered = desired
		if current == desired {
			return nil
		}
		configMap = configMap.DeepCopy()
		if configMap.Data == nil {
			configMap.Data = make(map[string]string)
		}
		configMap.Data[o.cfg.CoreDNSNodeHostsKey] = desired
		if _, err := configMaps.Update(ctx, configMap, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update CoreDNS NodeHosts ConfigMap %s/%s: %w", o.cfg.CoreDNSNamespace, o.cfg.CoreDNSConfigMapName, err)
		}
		return nil
	})
	return rendered, err
}

func (o *Operator) ensureCoreDNSReload(ctx context.Context, nodeHosts string) error {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(nodeHosts)))
	switch o.cfg.CoreDNSRolloutKind {
	case "deployment":
		deployments := o.kube.AppsV1().Deployments(o.cfg.CoreDNSNamespace)
		return retry.RetryOnConflict(retry.DefaultRetry, func() error {
			deployment, err := deployments.Get(ctx, o.cfg.CoreDNSRolloutName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("get CoreDNS Deployment %s/%s: %w", o.cfg.CoreDNSNamespace, o.cfg.CoreDNSRolloutName, err)
			}
			if deployment.Spec.Template.Annotations[nodeHostsHashAnnotation] == hash {
				return nil
			}
			deployment = deployment.DeepCopy()
			if deployment.Spec.Template.Annotations == nil {
				deployment.Spec.Template.Annotations = make(map[string]string)
			}
			deployment.Spec.Template.Annotations[nodeHostsHashAnnotation] = hash
			_, err = deployments.Update(ctx, deployment, metav1.UpdateOptions{})
			return err
		})
	case "daemonset":
		daemonSets := o.kube.AppsV1().DaemonSets(o.cfg.CoreDNSNamespace)
		return retry.RetryOnConflict(retry.DefaultRetry, func() error {
			daemonSet, err := daemonSets.Get(ctx, o.cfg.CoreDNSRolloutName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("get CoreDNS DaemonSet %s/%s: %w", o.cfg.CoreDNSNamespace, o.cfg.CoreDNSRolloutName, err)
			}
			if daemonSet.Spec.Template.Annotations[nodeHostsHashAnnotation] == hash {
				return nil
			}
			daemonSet = daemonSet.DeepCopy()
			if daemonSet.Spec.Template.Annotations == nil {
				daemonSet.Spec.Template.Annotations = make(map[string]string)
			}
			daemonSet.Spec.Template.Annotations[nodeHostsHashAnnotation] = hash
			_, err = daemonSets.Update(ctx, daemonSet, metav1.UpdateOptions{})
			return err
		})
	default:
		return fmt.Errorf("unsupported CoreDNS rollout kind %q", o.cfg.CoreDNSRolloutKind)
	}
}

func mergeManagedNodeHosts(current string, desiredHosts map[string]string) (string, error) {
	current = strings.ReplaceAll(current, "\r\n", "\n")
	lines := strings.Split(strings.TrimSuffix(current, "\n"), "\n")
	base := make([]string, 0, len(lines))
	inManagedBlock := false
	seenManagedBlock := false
	for _, line := range lines {
		switch strings.TrimSpace(line) {
		case nodeHostsBeginMarker:
			if inManagedBlock || seenManagedBlock {
				return "", errors.New("duplicate managed block begin marker")
			}
			inManagedBlock = true
			seenManagedBlock = true
		case nodeHostsEndMarker:
			if !inManagedBlock {
				return "", errors.New("managed block end marker has no matching begin marker")
			}
			inManagedBlock = false
		default:
			if !inManagedBlock {
				base = append(base, line)
			}
		}
	}
	if inManagedBlock {
		return "", errors.New("managed block begin marker has no matching end marker")
	}
	for len(base) > 0 && strings.TrimSpace(base[len(base)-1]) == "" {
		base = base[:len(base)-1]
	}

	hostnames := make([]string, 0, len(desiredHosts))
	for hostname := range desiredHosts {
		hostnames = append(hostnames, hostname)
	}
	sort.Strings(hostnames)
	if len(hostnames) > 0 {
		base = append(base, nodeHostsBeginMarker)
		for _, hostname := range hostnames {
			base = append(base, desiredHosts[hostname]+" "+hostname)
		}
		base = append(base, nodeHostsEndMarker)
	}
	if len(base) == 0 {
		return "", nil
	}
	return strings.Join(base, "\n") + "\n", nil
}
