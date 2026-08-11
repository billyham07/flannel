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
	"fmt"
	"net"
	"sort"

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

func newLocalRouteManager(cfg *runtimeConfig) (*netlinkRouteManager, error) {
	link, err := netlink.LinkByName(cfg.WARPInterface)
	if err != nil {
		return nil, fmt.Errorf("find WARP interface %q: %w", cfg.WARPInterface, err)
	}
	meshNetwork, err := parseCIDR(cfg.MeshCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse MeshCIDR: %w", err)
	}
	meshIP, err := findAddress(link, meshNetwork)
	if err != nil {
		return nil, err
	}
	table := cfg.RouteTable
	if table == 0 {
		table, err = detectWARPRouteTable(link, meshNetwork)
		if err != nil {
			return nil, err
		}
	}
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
		return fmt.Errorf("refresh WARP interface %q: %w", m.linkName, err)
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
		return fmt.Errorf("ensure WARP route %s in table %d: %w", network, m.table, err)
	}
	return nil
}

func (m *netlinkRouteManager) Remove(network string) error {
	link, err := netlink.LinkByName(m.linkName)
	if err != nil {
		return fmt.Errorf("refresh WARP interface %q: %w", m.linkName, err)
	}
	dst, err := parseCIDR(network)
	if err != nil {
		return err
	}
	filter := &netlink.Route{Dst: dst, Table: m.table}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list WARP route %s in table %d: %w", network, m.table, err)
	}
	for i := range routes {
		if routes[i].LinkIndex != link.Attrs().Index {
			continue
		}
		if err := netlink.RouteDel(&routes[i]); err != nil {
			return fmt.Errorf("remove WARP route %s from table %d: %w", network, m.table, err)
		}
	}
	return nil
}

func (m *netlinkRouteManager) MeshIP() net.IP { return append(net.IP(nil), m.meshIP...) }
func (m *netlinkRouteManager) MTU() int       { return m.mtu }
func (m *netlinkRouteManager) Table() int     { return m.table }

func detectWARPRouteTable(link netlink.Link, meshNetwork *net.IPNet) (int, error) {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return 0, fmt.Errorf("list IPv4 policy rules: %w", err)
	}
	tables := make(map[int]struct{})
	for _, rule := range rules {
		if rule.Table <= 0 || rule.Table == 253 || rule.Table == 254 || rule.Table == 255 {
			continue
		}
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: rule.Table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			continue
		}
		for _, route := range routes {
			if route.LinkIndex == link.Attrs().Index && route.Dst != nil && cidrsOverlap(route.Dst, meshNetwork) {
				tables[rule.Table] = struct{}{}
				break
			}
		}
	}
	if len(tables) != 1 {
		found := make([]int, 0, len(tables))
		for table := range tables {
			found = append(found, table)
		}
		sort.Ints(found)
		return 0, fmt.Errorf("expected one WARP policy route table for %s, found %v; set RouteTable explicitly", link.Attrs().Name, found)
	}
	for table := range tables {
		return table, nil
	}
	panic("unreachable")
}

func findAddress(link netlink.Link, network *net.IPNet) (net.IP, error) {
	addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("list addresses on %s: %w", link.Attrs().Name, err)
	}
	for _, address := range addresses {
		if address.IP != nil && network.Contains(address.IP) {
			return append(net.IP(nil), address.IP...), nil
		}
	}
	return nil, fmt.Errorf("interface %s has no address in MeshCIDR %s", link.Attrs().Name, network)
}

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
