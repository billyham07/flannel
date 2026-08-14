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
	"sort"
	"strings"
	"syscall"

	coreiptables "github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	log "k8s.io/klog/v2"
)

const hostSNATComment = "cloudflare-mesh hostNetwork SNAT"

const (
	meshRulePriority   = 109
	remoteRulePriority = 110
	snatChain          = "FLANNEL-POSTRTG"
)

type iptablesClient interface {
	Exists(table, chain string, rulespec ...string) (bool, error)
	Insert(table, chain string, pos int, rulespec ...string) error
	Delete(table, chain string, rulespec ...string) error
	List(table, chain string) ([]string, error)
}

// netlinkOps is the slice of the netlink package this backend uses. It exists
// so route reconciliation and teardown can be exercised without a live kernel
// routing table.
type netlinkOps interface {
	LinkByName(name string) (netlink.Link, error)
	RouteReplace(route *netlink.Route) error
	RouteListFiltered(family int, filter *netlink.Route, mask uint64) ([]netlink.Route, error)
	RouteDel(route *netlink.Route) error
	RuleAdd(rule *netlink.Rule) error
	RuleList(family int) ([]netlink.Rule, error)
	RuleDel(rule *netlink.Rule) error
}

type systemNetlink struct{}

func (systemNetlink) LinkByName(name string) (netlink.Link, error) { return netlink.LinkByName(name) }
func (systemNetlink) RouteReplace(route *netlink.Route) error      { return netlink.RouteReplace(route) }
func (systemNetlink) RouteDel(route *netlink.Route) error          { return netlink.RouteDel(route) }
func (systemNetlink) RuleAdd(rule *netlink.Rule) error             { return netlink.RuleAdd(rule) }
func (systemNetlink) RuleList(family int) ([]netlink.Rule, error)  { return netlink.RuleList(family) }
func (systemNetlink) RuleDel(rule *netlink.Rule) error             { return netlink.RuleDel(rule) }
func (systemNetlink) RouteListFiltered(family int, filter *netlink.Route, mask uint64) ([]netlink.Route, error) {
	return netlink.RouteListFiltered(family, filter, mask)
}

type localRouteManager interface {
	Ensure(network string) error
	Remove(network string) error
	Reconcile(desired map[string]struct{}) error
	Cleanup() error
	MeshIP() net.IP
	MTU() int
	Table() int
}

type netlinkRouteManager struct {
	linkName    string
	meshIP      net.IP
	mtu         int
	table       int
	meshCIDR    string
	clusterCIDR string
	localCIDR   string
	localSNATIP string
	iptables    iptablesClient
	nl          netlinkOps
}

func newLocalRouteManager(cfg *runtimeConfig, meshIP net.IP, clusterCIDR, localCIDR string) (*netlinkRouteManager, error) {
	nl := systemNetlink{}
	link, err := nl.LinkByName(cfg.InterfaceName)
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
	// A MeshCIDR that overlaps the cluster network would make the Mesh CIDR
	// route in the policy table shadow remote PodCIDRs, so refuse it up front
	// instead of blackholing pod traffic later.
	if cidrsOverlap(meshNetwork, clusterNetwork) {
		return nil, fmt.Errorf("MeshCIDR %s overlaps cluster network %s", meshNetwork, clusterNetwork)
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
		meshCIDR:    meshNetwork.String(),
		clusterCIDR: clusterNetwork.String(),
		localCIDR:   localNetwork.String(),
		localSNATIP: localSNATIP.String(),
		iptables:    ipt,
		nl:          nl,
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
	if err := m.nl.RouteReplace(&route); err != nil {
		return fmt.Errorf("ensure Mesh CIDR route %s in table %d: %w", meshNetwork, m.table, err)
	}
	rule := netlink.NewRule()
	rule.Priority = meshRulePriority
	rule.Table = m.table
	rule.Dst = meshNetwork
	if err := m.nl.RuleAdd(rule); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("ensure Mesh CIDR policy rule for %s: %w", meshNetwork, err)
	}
	return nil
}

func (m *netlinkRouteManager) Ensure(network string) error {
	link, err := m.nl.LinkByName(m.linkName)
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
	if err := m.nl.RouteReplace(&route); err != nil {
		return fmt.Errorf("ensure native Mesh route %s in table %d: %w", network, m.table, err)
	}
	rule := netlink.NewRule()
	rule.Priority = remoteRulePriority
	rule.Table = m.table
	rule.Dst = dst
	if err := m.nl.RuleAdd(rule); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("ensure native Mesh policy rule for %s: %w", network, err)
	}
	if err := m.ensureHostSNAT(dst); err != nil {
		return err
	}
	return nil
}

// Remove tears down every piece of state Ensure installed for one remote
// PodCIDR. It never looks up the Mesh link: the policy table is dedicated to
// this backend, so a route in it is ours by construction, and teardown has to
// keep working after the TUN device is already gone. Errors are collected
// rather than returned on the first failure so one wedged resource cannot
// strand the others.
func (m *netlinkRouteManager) Remove(network string) error {
	dst, err := parseCIDR(network)
	if err != nil {
		return err
	}
	var errs []error
	filter := &netlink.Route{Dst: dst, Table: m.table}
	routes, err := m.nl.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
	if err != nil {
		errs = append(errs, fmt.Errorf("list native Mesh route %s in table %d: %w", network, m.table, err))
	}
	for i := range routes {
		if err := m.nl.RouteDel(&routes[i]); err != nil && !errors.Is(err, syscall.ESRCH) {
			errs = append(errs, fmt.Errorf("remove native Mesh route %s from table %d: %w", network, m.table, err))
		}
	}
	rules, err := m.nl.RuleList(netlink.FAMILY_V4)
	if err != nil {
		errs = append(errs, fmt.Errorf("list native Mesh policy rules: %w", err))
	}
	for i := range rules {
		if rules[i].Table == m.table && rules[i].Priority == remoteRulePriority && rules[i].Dst != nil && rules[i].Dst.String() == dst.String() {
			if err := m.nl.RuleDel(&rules[i]); err != nil && !errors.Is(err, syscall.ENOENT) {
				errs = append(errs, fmt.Errorf("remove native Mesh policy rule for %s: %w", network, err))
			}
		}
	}
	if err := m.removeHostSNAT(dst); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Reconcile drives the policy table towards exactly the set of remote PodCIDRs
// flannel currently leases. Ensuring alone is not enough: leases that
// disappeared while flanneld was down produce no removal event, so their routes
// would otherwise survive forever and blackhole a recycled PodCIDR.
func (m *netlinkRouteManager) Reconcile(desired map[string]struct{}) error {
	var errs []error
	for network := range desired {
		if err := m.Ensure(network); err != nil {
			errs = append(errs, err)
		}
	}
	stale, err := m.staleDestinations(desired)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, network := range stale {
		log.Infof("cloudflare-mesh: pruning stale route %s from table %d", network, m.table)
		if err := m.Remove(network); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Cleanup removes everything this node installed. flanneld waits for the
// backend's Run to return before exiting, which makes this the last chance to
// leave the host without a dedicated routing table, orphan policy rules or a
// SNAT rule pointing at an interface that no longer exists.
func (m *netlinkRouteManager) Cleanup() error {
	var errs []error
	snat, err := m.managedSNATDestinations()
	if err != nil {
		errs = append(errs, err)
	}
	for _, network := range snat {
		dst, err := parseCIDR(network)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := m.removeHostSNAT(dst); err != nil {
			errs = append(errs, err)
		}
	}
	routes, err := m.nl.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: m.table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		errs = append(errs, fmt.Errorf("list native Mesh routes in table %d: %w", m.table, err))
	}
	for i := range routes {
		if err := m.nl.RouteDel(&routes[i]); err != nil && !errors.Is(err, syscall.ESRCH) {
			errs = append(errs, fmt.Errorf("remove native Mesh route from table %d: %w", m.table, err))
		}
	}
	rules, err := m.nl.RuleList(netlink.FAMILY_V4)
	if err != nil {
		errs = append(errs, fmt.Errorf("list native Mesh policy rules: %w", err))
	}
	for i := range rules {
		if rules[i].Table != m.table {
			continue
		}
		if rules[i].Priority != meshRulePriority && rules[i].Priority != remoteRulePriority {
			continue
		}
		if err := m.nl.RuleDel(&rules[i]); err != nil && !errors.Is(err, syscall.ENOENT) {
			errs = append(errs, fmt.Errorf("remove native Mesh policy rule: %w", err))
		}
	}
	return errors.Join(errs...)
}

// staleDestinations reports the remote PodCIDRs that still have state on the
// host but no longer have a lease. Routes, policy rules and SNAT rules are
// checked independently because a crash between the three deletions in Remove
// leaves only some of them behind.
func (m *netlinkRouteManager) staleDestinations(desired map[string]struct{}) ([]string, error) {
	found := make(map[string]struct{})
	routes, err := m.nl.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: m.table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("list native Mesh routes in table %d: %w", m.table, err)
	}
	for i := range routes {
		if routes[i].Dst == nil {
			continue
		}
		found[routes[i].Dst.String()] = struct{}{}
	}
	rules, err := m.nl.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("list native Mesh policy rules: %w", err)
	}
	for i := range rules {
		if rules[i].Table == m.table && rules[i].Priority == remoteRulePriority && rules[i].Dst != nil {
			found[rules[i].Dst.String()] = struct{}{}
		}
	}
	snat, err := m.managedSNATDestinations()
	if err != nil {
		return nil, err
	}
	for _, network := range snat {
		found[network] = struct{}{}
	}

	stale := make([]string, 0, len(found))
	for network := range found {
		// The Mesh CIDR route is infrastructure rather than a lease, and is
		// only removed by Cleanup.
		if network == m.meshCIDR {
			continue
		}
		if _, ok := desired[network]; ok {
			continue
		}
		stale = append(stale, network)
	}
	sort.Strings(stale)
	return stale, nil
}

func (m *netlinkRouteManager) managedSNATDestinations() ([]string, error) {
	rules, err := m.iptables.List("nat", snatChain)
	if err != nil {
		// trafficmngr owns the chain; before it has created it there is
		// nothing of ours to prune.
		var iptErr *coreiptables.Error
		if errors.As(err, &iptErr) && iptErr.IsNotExist() {
			return nil, nil
		}
		return nil, fmt.Errorf("list hostNetwork SNAT rules: %w", err)
	}
	return snatDestinations(rules), nil
}

// snatDestinations picks the -d destination out of every rule carrying our
// comment, so a SNAT entry orphaned by a crash is prunable even once its route
// and policy rule are gone.
func snatDestinations(rules []string) []string {
	var destinations []string
	for _, rule := range rules {
		if !strings.Contains(rule, hostSNATComment) {
			continue
		}
		fields := strings.Fields(rule)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] != "-d" {
				continue
			}
			if _, network, err := net.ParseCIDR(fields[i+1]); err == nil {
				destinations = append(destinations, network.String())
			}
			break
		}
	}
	return destinations
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
