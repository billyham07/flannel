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
	"fmt"
	"os/exec"
	"strings"

	log "k8s.io/klog/v2"
)

const legacyWARPFirewallTable = "cloudflare-warp"

// removeLegacyWARPFirewall removes the nftables kill-switch left behind by
// warp-svc. Its input and output chains explicitly drop Cloudflare's
// 100.96.0.0/12 virtual-IP range unless traffic leaves through the old
// CloudflareWARP interface, so keeping it makes the native TUN fail locally
// with EPERM even when the MASQUE session and policy routes are healthy.
func removeLegacyWARPFirewall(ctx context.Context) error {
	output, err := exec.CommandContext(ctx, "nft", "delete", "table", "inet", legacyWARPFirewallTable).CombinedOutput()
	if err == nil {
		log.Infof("cloudflare-mesh: removed legacy warp-svc nftables table %q", legacyWARPFirewallTable)
		return nil
	}
	return legacyWARPFirewallDeleteError(output, err)
}

func legacyWARPFirewallDeleteError(output []byte, commandErr error) error {
	message := strings.TrimSpace(string(output))
	lower := strings.ToLower(message)
	if strings.Contains(lower, "no such file or directory") || strings.Contains(lower, "does not exist") {
		return nil
	}
	if message == "" {
		return fmt.Errorf("remove legacy warp-svc nftables table: %w", commandErr)
	}
	return fmt.Errorf("remove legacy warp-svc nftables table: %w: %s", commandErr, message)
}
