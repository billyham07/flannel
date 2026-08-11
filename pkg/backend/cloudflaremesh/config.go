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

package cloudflaremesh

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	defaultAPIBaseURL      = "https://api.cloudflare.com/client/v4"
	defaultControlPlane    = "operator"
	defaultTokenFile       = "/var/run/secrets/cloudflare-mesh/api-token"
	defaultOperatorNS      = "kube-flannel"
	defaultSecretPrefix    = "cloudflare-mesh-node-"
	defaultStateFile       = "/var/lib/flannel/cloudflare-mesh/state.json"
	defaultWARPCLI         = "warp-cli"
	defaultWARPMode        = "host-cli"
	defaultWARPInterface   = "CloudflareWARP"
	defaultMeshCIDR        = "100.96.0.0/12"
	defaultConnectTimeout  = 45 * time.Second
	defaultBootstrapWait   = 2 * time.Minute
	defaultReconcilePeriod = 30 * time.Second
	cloudflareAPITokenEnv  = "CLOUDFLARE_API_TOKEN"
	cloudflareAccountIDEnv = "CLOUDFLARE_ACCOUNT_ID"
	cloudflareNodeNameEnv  = "NODE_NAME"
)

type config struct {
	ControlPlaneMode          string   `json:"ControlPlaneMode"`
	AccountID                 string   `json:"AccountID"`
	APITokenFile              string   `json:"APITokenFile"`
	APIBaseURL                string   `json:"APIBaseURL"`
	NodeName                  string   `json:"NodeName"`
	ConnectorID               string   `json:"ConnectorID"`
	ConnectorHA               bool     `json:"ConnectorHA"`
	OperatorNamespace         string   `json:"OperatorNamespace"`
	OperatorSecretPrefix      string   `json:"OperatorSecretPrefix"`
	Kubeconfig                string   `json:"Kubeconfig"`
	BootstrapTimeout          string   `json:"BootstrapTimeout"`
	AdoptExistingRegistration bool     `json:"AdoptExistingRegistration"`
	StateFile                 string   `json:"StateFile"`
	WARPCLI                   string   `json:"WARPCLI"`
	WARPCLIArgs               []string `json:"WARPCLIArgs"`
	WARPMode                  string   `json:"WARPMode"`
	WARPInterface             string   `json:"WARPInterface"`
	MeshCIDR                  string   `json:"MeshCIDR"`
	RouteTable                int      `json:"RouteTable"`
	ConnectTimeout            string   `json:"ConnectTimeout"`
	ReconcilePeriod           string   `json:"ReconcilePeriod"`
}

type runtimeConfig struct {
	config
	APIToken       string
	ConnectWait    time.Duration
	BootstrapWait  time.Duration
	ReconcileEvery time.Duration
}

func loadConfig(raw json.RawMessage) (*runtimeConfig, error) {
	cfg := config{
		ControlPlaneMode:     defaultControlPlane,
		APITokenFile:         defaultTokenFile,
		APIBaseURL:           defaultAPIBaseURL,
		OperatorNamespace:    defaultOperatorNS,
		OperatorSecretPrefix: defaultSecretPrefix,
		StateFile:            defaultStateFile,
		WARPCLI:              defaultWARPCLI,
		WARPMode:             defaultWARPMode,
		WARPInterface:        defaultWARPInterface,
		MeshCIDR:             defaultMeshCIDR,
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("decode cloudflare-mesh backend config: %w", err)
		}
	}

	if cfg.ControlPlaneMode != "operator" && cfg.ControlPlaneMode != "direct" {
		return nil, fmt.Errorf("ControlPlaneMode must be operator or direct, got %q", cfg.ControlPlaneMode)
	}
	if cfg.WARPMode != "host-cli" && cfg.WARPMode != "external" {
		return nil, fmt.Errorf("WARPMode must be host-cli or external, got %q", cfg.WARPMode)
	}

	if cfg.NodeName == "" {
		cfg.NodeName = os.Getenv(cloudflareNodeNameEnv)
	}
	if cfg.NodeName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("determine node name: %w", err)
		}
		cfg.NodeName = hostname
	}
	if strings.TrimSpace(cfg.NodeName) == "" {
		return nil, errors.New("cloudflare Mesh node name must not be empty")
	}

	token := ""
	if cfg.ControlPlaneMode == "direct" {
		if cfg.AccountID == "" {
			cfg.AccountID = os.Getenv(cloudflareAccountIDEnv)
		}
		if cfg.AccountID == "" {
			return nil, fmt.Errorf("cloudflare account ID must be set with AccountID or %s", cloudflareAccountIDEnv)
		}
		token = strings.TrimSpace(os.Getenv(cloudflareAPITokenEnv))
		if token == "" {
			contents, err := os.ReadFile(cfg.APITokenFile)
			if err != nil {
				return nil, fmt.Errorf("read Cloudflare API token file %q: %w", cfg.APITokenFile, err)
			}
			token = strings.TrimSpace(string(contents))
		}
		if token == "" {
			return nil, errors.New("Cloudflare API token must not be empty")
		}
	}

	connectWait, err := parseDuration(cfg.ConnectTimeout, defaultConnectTimeout, "ConnectTimeout")
	if err != nil {
		return nil, err
	}
	bootstrapWait, err := parseDuration(cfg.BootstrapTimeout, defaultBootstrapWait, "BootstrapTimeout")
	if err != nil {
		return nil, err
	}
	reconcileEvery, err := parseDuration(cfg.ReconcilePeriod, defaultReconcilePeriod, "ReconcilePeriod")
	if err != nil {
		return nil, err
	}

	return &runtimeConfig{
		config:         cfg,
		APIToken:       token,
		ConnectWait:    connectWait,
		BootstrapWait:  bootstrapWait,
		ReconcileEvery: reconcileEvery,
	}, nil
}

func parseDuration(value string, fallback time.Duration, field string) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", field, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", field)
	}
	return d, nil
}
