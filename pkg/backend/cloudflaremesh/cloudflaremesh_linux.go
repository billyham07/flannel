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
	"encoding/json"
	"fmt"
	"sync"

	"github.com/flannel-io/flannel/pkg/backend"
	meshapi "github.com/flannel-io/flannel/pkg/cloudflaremesh"
	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/pkg/lease"
	"github.com/flannel-io/flannel/pkg/subnet"
	log "k8s.io/klog/v2"
)

type meshBackend struct {
	sm subnet.Manager
}

func init() {
	backend.Register(meshapi.BackendName, New)
}

func New(sm subnet.Manager, _ *backend.ExternalInterface) (backend.Backend, error) {
	return &meshBackend{sm: sm}, nil
}

func (b *meshBackend) RegisterNetwork(ctx context.Context, _ *sync.WaitGroup, networkConfig *subnet.Config) (backend.Network, error) {
	if networkConfig.EnableIPv6 {
		return nil, fmt.Errorf("%s backend does not support IPv6 yet", meshapi.BackendName)
	}
	cfg, err := loadConfig(networkConfig.Backend)
	if err != nil {
		return nil, err
	}
	var connector *meshapi.ConnectorCredentials
	var api meshapi.API
	if cfg.ControlPlaneMode == "operator" {
		connector, err = waitForOperatorCredentials(ctx, cfg)
	} else {
		api, err = meshapi.NewClient(cfg.APIBaseURL, cfg.AccountID, cfg.APIToken, nil)
		if err == nil {
			connector, err = api.EnsureConnector(ctx, cfg.ConnectorID, cfg.NodeName, cfg.ConnectorHA)
		}
	}
	if err != nil {
		return nil, err
	}
	if cfg.WARPMode == "host-cli" {
		if err := newWARPClient(cfg).EnsureRegisteredAndConnected(ctx, connector, cfg.AdoptExistingRegistration); err != nil {
			return nil, err
		}
	}
	routes, err := waitForLocalRouteManager(ctx, cfg)
	if err != nil {
		return nil, err
	}

	backendData, err := json.Marshal(meshapi.LeaseData{ConnectorID: connector.ID, MeshIP: routes.MeshIP().String()})
	if err != nil {
		return nil, fmt.Errorf("encode cloudflare-mesh lease data: %w", err)
	}
	attrs := lease.LeaseAttrs{
		PublicIP:    ip.FromIP(routes.MeshIP()),
		BackendType: meshapi.BackendName,
		BackendData: backendData,
	}
	localLease, err := b.sm.AcquireLease(ctx, &attrs)
	if err != nil {
		return nil, fmt.Errorf("acquire cloudflare-mesh subnet lease: %w", err)
	}
	if api != nil {
		comment := fmt.Sprintf("flannel:%s:%s", cfg.NodeName, localLease.Subnet)
		if _, err := api.EnsureRoute(ctx, connector.ID, localLease.Subnet.String(), comment); err != nil {
			return nil, err
		}
	}

	log.Infof("cloudflare-mesh: node=%s connector=%s meshIP=%s podCIDR=%s routeTable=%d mtu=%d",
		cfg.NodeName, connector.ID, routes.MeshIP(), localLease.Subnet, routes.Table(), routes.MTU())
	return &meshNetwork{
		lease:          localLease,
		sm:             b.sm,
		routes:         routes,
		reconcileEvery: cfg.ReconcileEvery,
		desired:        make(map[string]struct{}),
	}, nil
}
