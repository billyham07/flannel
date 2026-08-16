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
	defaultOperatorNS      = "kube-flannel"
	defaultSecretPrefix    = "cloudflare-mesh-node-"
	defaultStateFile       = "/var/lib/flannel/cloudflare-mesh/state.json"
	defaultInterfaceName   = "flannel.mesh"
	defaultMeshCIDR        = "100.96.0.0/12"
	defaultRouteTable      = 51820
	defaultMTU             = 1280
	defaultKeepalive       = 30 * time.Second
	defaultConnectTimeout  = 45 * time.Second
	defaultBootstrapWait   = 2 * time.Minute
	defaultReconcilePeriod = 30 * time.Second
	cloudflareNodeNameEnv  = "NODE_NAME"
)

// config is the backend stanza of net-conf.json. The Cloudflare account
// credentials deliberately do not appear here: every node gets its connector
// from the operator's per-node bootstrap Secret, so the account API token stays
// confined to the operator.
type config struct {
	NodeName             string `json:"NodeName"`
	OperatorNamespace    string `json:"OperatorNamespace"`
	OperatorSecretPrefix string `json:"OperatorSecretPrefix"`
	Kubeconfig           string `json:"Kubeconfig"`
	BootstrapTimeout     string `json:"BootstrapTimeout"`
	StateFile            string `json:"StateFile"`
	InterfaceName        string `json:"InterfaceName"`
	MeshCIDR             string `json:"MeshCIDR"`
	RouteTable           int    `json:"RouteTable"`
	MTU                  int    `json:"MTU"`
	ConnectTimeout       string `json:"ConnectTimeout"`
	KeepalivePeriod      string `json:"KeepalivePeriod"`
	ReconcilePeriod      string `json:"ReconcilePeriod"`
}

type runtimeConfig struct {
	config
	ConnectWait    time.Duration
	BootstrapWait  time.Duration
	ReconcileEvery time.Duration
	KeepaliveEvery time.Duration
}

func loadConfig(raw json.RawMessage) (*runtimeConfig, error) {
	cfg := config{
		OperatorNamespace:    defaultOperatorNS,
		OperatorSecretPrefix: defaultSecretPrefix,
		StateFile:            defaultStateFile,
		InterfaceName:        defaultInterfaceName,
		MeshCIDR:             defaultMeshCIDR,
		RouteTable:           defaultRouteTable,
		MTU:                  defaultMTU,
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("decode cloudflare-mesh backend config: %w", err)
		}
	}

	if cfg.InterfaceName == "" || len(cfg.InterfaceName) > 15 {
		return nil, fmt.Errorf("InterfaceName must be 1-15 bytes")
	}
	if cfg.RouteTable <= 0 {
		return nil, fmt.Errorf("RouteTable must be greater than zero")
	}
	if cfg.MTU < 1280 {
		return nil, fmt.Errorf("MTU must be at least 1280")
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

	keepaliveEvery, err := parseDuration(cfg.KeepalivePeriod, defaultKeepalive, "KeepalivePeriod")
	if err != nil {
		return nil, err
	}

	return &runtimeConfig{
		config:         cfg,
		ConnectWait:    connectWait,
		BootstrapWait:  bootstrapWait,
		ReconcileEvery: reconcileEvery,
		KeepaliveEvery: keepaliveEvery,
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
