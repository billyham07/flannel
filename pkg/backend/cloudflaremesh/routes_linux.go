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
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
)

type localRouteManager interface {
	Ensure(network string) error
	Remove(network string) error
	MeshIP() net.IP
	MTU() int
	Table() int
}

type netlinkRouteManager struct {
	linkName string
	meshIP   net.IP
	mtu      int
	table    int
}

func newLocalRouteManager(cfg *runtimeConfig, meshIP net.IP) (*netlinkRouteManager, error) {
	link, err := netlink.LinkByName(cfg.InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("find native Mesh interface %q: %w", cfg.InterfaceName, err)
	}
	meshNetwork, err := parseCIDR(cfg.MeshCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse MeshCIDR: %w", err)
	}
	if meshIP == nil || !meshNetwork.Contains(meshIP) {
		return nil, fmt.Errorf("native Mesh address %v outside %s", meshIP, meshNetwork)
	}
	table := cfg.RouteTable
	return &netlinkRouteManager{
		linkName: link.Attrs().Name,
		meshIP:   meshIP,
		mtu:      link.Attrs().MTU,
		table:    table,
	}, nil
}

func (m *netlinkRouteManager) Ensure(network string) error {
	link, err := netlink.LinkByName(m.linkName)
	if err != nil {
		return fmt.Errorf("refresh native Mesh interface %q: %w", m.linkName, err)
	}
	dst, err := parseCIDR(network)
	if err != nil {
		return err
	}
	route := netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       dst,
		Table:     m.table,
	}
	if err := netlink.RouteReplace(&route); err != nil {
		return fmt.Errorf("ensure native Mesh route %s in table %d: %w", network, m.table, err)
	}
	rule := netlink.NewRule()
	rule.Priority = 110
	rule.Table = m.table
	rule.Dst = dst
	if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("ensure native Mesh policy rule for %s: %w", network, err)
	}
	return nil
}

func (m *netlinkRouteManager) Remove(network string) error {
	link, err := netlink.LinkByName(m.linkName)
	if err != nil {
		return fmt.Errorf("refresh native Mesh interface %q: %w", m.linkName, err)
	}
	dst, err := parseCIDR(network)
	if err != nil {
		return err
	}
	filter := &netlink.Route{Dst: dst, Table: m.table}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list native Mesh route %s in table %d: %w", network, m.table, err)
	}
	for i := range routes {
		if routes[i].LinkIndex != link.Attrs().Index {
			continue
		}
		if err := netlink.RouteDel(&routes[i]); err != nil {
			return fmt.Errorf("remove native Mesh route %s from table %d: %w", network, m.table, err)
		}
	}
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list native Mesh policy rules: %w", err)
	}
	for i := range rules {
		if rules[i].Table == m.table && rules[i].Priority == 110 && rules[i].Dst != nil && rules[i].Dst.String() == dst.String() {
			if err := netlink.RuleDel(&rules[i]); err != nil && !errors.Is(err, syscall.ENOENT) {
				return fmt.Errorf("remove native Mesh policy rule for %s: %w", network, err)
			}
		}
	}
	return nil
}

func (m *netlinkRouteManager) MeshIP() net.IP { return append(net.IP(nil), m.meshIP...) }
func (m *netlinkRouteManager) MTU() int       { return m.mtu }
func (m *netlinkRouteManager) Table() int     { return m.table }

func parseCIDR(value string) (*net.IPNet, error) {
	ipAddress, network, err := net.ParseCIDR(value)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %q: %w", value, err)
	}
	if ipAddress.To4() == nil {
		return nil, fmt.Errorf("CIDR %q is not IPv4", value)
	}
	network.IP = ipAddress.To4()
	return network, nil
}

func cidrsOverlap(first, second *net.IPNet) bool {
	return first.Contains(second.IP) || second.Contains(first.IP)
}
