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

	coreiptables "github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
)

const hostSNATComment = "cloudflare-mesh hostNetwork SNAT"

const (
	meshRulePriority   = 109
	remoteRulePriority = 110
)

type iptablesClient interface {
	Exists(table, chain string, rulespec ...string) (bool, error)
	Insert(table, chain string, pos int, rulespec ...string) error
	Delete(table, chain string, rulespec ...string) error
}

type localRouteManager interface {
	Ensure(network string) error
	Remove(network string) error
	MeshIP() net.IP
	MTU() int
	Table() int
}

type netlinkRouteManager struct {
	linkName    string
	meshIP      net.IP
	mtu         int
	table       int
	clusterCIDR string
	localCIDR   string
	localSNATIP string
	iptables    iptablesClient
}

func newLocalRouteManager(cfg *runtimeConfig, meshIP net.IP, clusterCIDR, localCIDR string) (*netlinkRouteManager, error) {
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
	clusterNetwork, err := parseCIDR(clusterCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse cluster network: %w", err)
	}
	localNetwork, err := parseCIDR(localCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse local PodCIDR: %w", err)
	}
	if !clusterNetwork.Contains(localNetwork.IP) || !clusterNetwork.Contains(lastIPv4(localNetwork)) {
		return nil, fmt.Errorf("local PodCIDR %s is outside cluster network %s", localNetwork, clusterNetwork)
	}
	localSNATIP, err := firstUsableIPv4(localNetwork)
	if err != nil {
		return nil, err
	}
	ipt, err := coreiptables.NewWithProtocol(coreiptables.ProtocolIPv4)
	if err != nil {
		return nil, fmt.Errorf("initialize hostNetwork SNAT: %w", err)
	}
	table := cfg.RouteTable
	manager := &netlinkRouteManager{
		linkName:    link.Attrs().Name,
		meshIP:      meshIP,
		mtu:         link.Attrs().MTU,
		table:       table,
		clusterCIDR: clusterNetwork.String(),
		localCIDR:   localNetwork.String(),
		localSNATIP: localSNATIP.String(),
		iptables:    ipt,
	}
	if err := manager.ensureMeshRoute(link, meshNetwork); err != nil {
		return nil, err
	}
	return manager, nil
}

// ensureMeshRoute makes connector virtual addresses first-class tunnel
// destinations. Cloudflare reserves 100.96.0.0/12 for WARP virtual IPs, but a
// /32 address on a TUN device does not create an on-link route automatically.
func (m *netlinkRouteManager) ensureMeshRoute(link netlink.Link, meshNetwork *net.IPNet) error {
	route := netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       meshNetwork,
		Table:     m.table,
	}
	if err := netlink.RouteReplace(&route); err != nil {
		return fmt.Errorf("ensure Mesh CIDR route %s in table %d: %w", meshNetwork, m.table, err)
	}
	rule := netlink.NewRule()
	rule.Priority = meshRulePriority
	rule.Table = m.table
	rule.Dst = meshNetwork
	if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("ensure Mesh CIDR policy rule for %s: %w", meshNetwork, err)
	}
	return nil
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
	rule.Priority = remoteRulePriority
	rule.Table = m.table
	rule.Dst = dst
	if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("ensure native Mesh policy rule for %s: %w", network, err)
	}
	if err := m.ensureHostSNAT(dst); err != nil {
		return err
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
		if rules[i].Table == m.table && rules[i].Priority == remoteRulePriority && rules[i].Dst != nil && rules[i].Dst.String() == dst.String() {
			if err := netlink.RuleDel(&rules[i]); err != nil && !errors.Is(err, syscall.ENOENT) {
				return fmt.Errorf("remove native Mesh policy rule for %s: %w", network, err)
			}
		}
	}
	return m.removeHostSNAT(dst)
}

func (m *netlinkRouteManager) ensureHostSNAT(dst *net.IPNet) error {
	rule := m.hostSNATRule(dst)
	exists, err := m.iptables.Exists("nat", "FLANNEL-POSTRTG", rule...)
	if err != nil {
		return fmt.Errorf("check hostNetwork SNAT for %s: %w", dst, err)
	}
	if exists {
		return nil
	}
	if err := m.iptables.Insert("nat", "FLANNEL-POSTRTG", 2, rule...); err != nil {
		return fmt.Errorf("ensure hostNetwork SNAT for %s: %w", dst, err)
	}
	return nil
}

func (m *netlinkRouteManager) removeHostSNAT(dst *net.IPNet) error {
	rule := m.hostSNATRule(dst)
	exists, err := m.iptables.Exists("nat", "FLANNEL-POSTRTG", rule...)
	if err != nil {
		return fmt.Errorf("check hostNetwork SNAT for %s: %w", dst, err)
	}
	if !exists {
		return nil
	}
	if err := m.iptables.Delete("nat", "FLANNEL-POSTRTG", rule...); err != nil {
		return fmt.Errorf("remove hostNetwork SNAT for %s: %w", dst, err)
	}
	return nil
}

func (m *netlinkRouteManager) hostSNATRule(dst *net.IPNet) []string {
	return []string{
		"!", "-s", m.clusterCIDR,
		"-d", dst.String(),
		"-m", "addrtype", "--src-type", "LOCAL",
		"-o", m.linkName,
		"-m", "comment", "--comment", hostSNATComment,
		"-j", "SNAT", "--to-source", m.localSNATIP,
	}
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

func firstUsableIPv4(network *net.IPNet) (net.IP, error) {
	if network == nil || network.IP.To4() == nil {
		return nil, errors.New("local PodCIDR is not IPv4")
	}
	first := append(net.IP(nil), network.IP.To4()...)
	for i := len(first) - 1; i >= 0; i-- {
		first[i]++
		if first[i] != 0 {
			break
		}
	}
	if !network.Contains(first) || first.Equal(lastIPv4(network)) {
		return nil, fmt.Errorf("local PodCIDR %s has no usable gateway address", network)
	}
	return first, nil
}

func lastIPv4(network *net.IPNet) net.IP {
	ip := append(net.IP(nil), network.IP.To4()...)
	for i := range ip {
		ip[i] |= ^network.Mask[i]
	}
	return ip
}
