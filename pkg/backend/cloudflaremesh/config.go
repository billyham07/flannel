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

// quicDatagramOverhead is how much larger a QUIC packet is than the IP packet
// it carries, on the CONNECT-IP-over-HTTP/3 path:
//
//	 1  CONNECT-IP context ID varint
//	 4  HTTP/3 quarter-stream-ID varint (1 for this first request stream, plus
//	    conservative slack; the TUN buffer reserves the full 8-byte maximum)
//	 3  DATAGRAM frame type plus its length varint
//	37  what quic-go conservatively reserves for the short header and the AEAD
//	    tag when it decides whether a datagram fits (1 type + 20 connection ID
//	    + 16 tag)
//
// quic-go rejects a datagram unless the connection's current packet size can
// hold all of it, so a MASQUE session can only carry a full-MTU packet once
// its packet size is at least MTU+quicDatagramOverhead.
const quicDatagramOverhead = 45

// maxQUICPacketSize mirrors quic-go's protocol.MaxPacketBufferSize, the largest
// packet it will ever send.
const maxQUICPacketSize = 1452

// quicInitialPacketSize is the packet size a session starts at, sized so a
// full-MTU packet fits from the first datagram onwards.
//
// Without this quic-go starts every session at 1280 bytes and only grows via
// path MTU discovery, which leaves a window -- and, on a path whose MTU never
// reaches MTU+quicDatagramOverhead, a permanent state -- where every full-size
// pod packet is rejected. Those rejections are invisible: connect-ip answers
// them with an ICMP "fragmentation needed" quoting 1280, which is already the
// TUN MTU, so the sender has nothing to shrink and just retransmits.
func quicInitialPacketSize(mtu int) uint16 {
	return uint16(min(mtu+quicDatagramOverhead, maxQUICPacketSize))
}

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
	// A larger MTU than this cannot be carried: the CONNECT-IP datagram that
	// wraps the packet would not fit in the largest QUIC packet quic-go will
	// ever send, so every full-size packet would be silently dropped.
	if maxMTU := maxQUICPacketSize - quicDatagramOverhead; cfg.MTU > maxMTU {
		return nil, fmt.Errorf("MTU must be at most %d, the largest packet a CONNECT-IP datagram can carry", maxMTU)
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
