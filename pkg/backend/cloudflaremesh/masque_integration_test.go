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
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	meshapi "github.com/flannel-io/flannel/pkg/cloudflaremesh"
)

func TestConnectorEnrollmentIntegration(t *testing.T) {
	connectorID := os.Getenv("CLOUDFLARE_MESH_TEST_CONNECTOR_ID")
	token := os.Getenv("CLOUDFLARE_MESH_TEST_CONNECTOR_TOKEN")
	if connectorID == "" || token == "" {
		t.Skip("Cloudflare Mesh integration credentials are not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cfg := &runtimeConfig{
		config:      config{StateFile: filepath.Join(t.TempDir(), "state.json"), NodeName: "flannel-native-integration"},
		ConnectWait: 45 * time.Second,
	}
	registration, key, err := loadOrEnroll(ctx, cfg, &meshapi.ConnectorCredentials{ID: connectorID, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	if key == nil || !registration.IsConnector || registration.Account.AccountType != "team" {
		t.Fatalf("unexpected connector registration: key=%t connector=%t account=%q", key != nil, registration.IsConnector, registration.Account.AccountType)
	}
	if ip := net.ParseIP(registration.Config.Interface.Addresses.V4); ip == nil || ip.To4() == nil {
		t.Fatalf("invalid connector Mesh IPv4 %q", registration.Config.Interface.Addresses.V4)
	}
	if len(registration.Config.Peers) == 0 {
		t.Fatal("connector registration returned no MASQUE peers")
	}
	if _, err := parseEndpointKey(registration.Config.Peers[0].PublicKey); err != nil {
		t.Fatalf("invalid MASQUE endpoint key: %v", err)
	}
}
