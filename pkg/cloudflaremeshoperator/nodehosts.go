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
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

const (
	nodeHostsBeginMarker = "# BEGIN cloudflare-mesh-operator"
	nodeHostsEndMarker   = "# END cloudflare-mesh-operator"
)

func (o *Operator) ensureCoreDNSNodeHosts(ctx context.Context, desiredHosts map[string]string) error {
	configMaps := o.kube.CoreV1().ConfigMaps(o.cfg.CoreDNSNamespace)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		configMap, err := configMaps.Get(ctx, o.cfg.CoreDNSConfigMapName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get CoreDNS NodeHosts ConfigMap %s/%s: %w", o.cfg.CoreDNSNamespace, o.cfg.CoreDNSConfigMapName, err)
		}
		current := configMap.Data[o.cfg.CoreDNSNodeHostsKey]
		desired, err := mergeManagedNodeHosts(current, desiredHosts)
		if err != nil {
			return fmt.Errorf("merge CoreDNS NodeHosts: %w", err)
		}
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
