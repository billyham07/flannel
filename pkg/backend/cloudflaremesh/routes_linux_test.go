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
	"net"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
)

type fakeIPTables struct {
	rules    [][]string
	inserted []string
	deleted  []string
}

func (f *fakeIPTables) index(rulespec []string) int {
	return slices.IndexFunc(f.rules, func(rule []string) bool { return slices.Equal(rule, rulespec) })
}

func (f *fakeIPTables) Exists(_, _ string, rulespec ...string) (bool, error) {
	return f.index(rulespec) >= 0, nil
}
func (f *fakeIPTables) Insert(_, _ string, _ int, rulespec ...string) error {
	f.rules = append(f.rules, slices.Clone(rulespec))
	f.inserted = slices.Clone(rulespec)
	return nil
}
func (f *fakeIPTables) Delete(_, _ string, rulespec ...string) error {
	if i := f.index(rulespec); i >= 0 {
		f.rules = slices.Delete(f.rules, i, i+1)
	}
	f.deleted = slices.Clone(rulespec)
	return nil
}
func (f *fakeIPTables) List(_, _ string) ([]string, error) {
	lines := make([]string, 0, len(f.rules))
	for _, rule := range f.rules {
		lines = append(lines, "-A "+snatChain+" "+strings.Join(rule, " "))
	}
	return lines, nil
}

type fakeNetlink struct {
	link   netlink.Link
	routes []netlink.Route
	rules  []netlink.Rule
}

func sameDst(first, second *net.IPNet) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	return first.String() == second.String()
}

func (f *fakeNetlink) LinkByName(name string) (netlink.Link, error) {
	if f.link == nil || f.link.Attrs().Name != name {
		return nil, netlink.LinkNotFoundError{}
	}
	return f.link, nil
}

func (f *fakeNetlink) RouteReplace(route *netlink.Route) error {
	for i := range f.routes {
		if f.routes[i].Table == route.Table && sameDst(f.routes[i].Dst, route.Dst) {
			f.routes[i] = *route
			return nil
		}
	}
	f.routes = append(f.routes, *route)
	return nil
}

func (f *fakeNetlink) RouteListFiltered(_ int, filter *netlink.Route, mask uint64) ([]netlink.Route, error) {
	var matched []netlink.Route
	for _, route := range f.routes {
		if mask&netlink.RT_FILTER_TABLE != 0 && route.Table != filter.Table {
			continue
		}
		if mask&netlink.RT_FILTER_DST != 0 && !sameDst(route.Dst, filter.Dst) {
			continue
		}
		matched = append(matched, route)
	}
	return matched, nil
}

func (f *fakeNetlink) RouteDel(route *netlink.Route) error {
	for i := range f.routes {
		if f.routes[i].Table == route.Table && sameDst(f.routes[i].Dst, route.Dst) {
			f.routes = slices.Delete(f.routes, i, i+1)
			return nil
		}
	}
	return syscall.ESRCH
}

func (f *fakeNetlink) RuleAdd(rule *netlink.Rule) error {
	for i := range f.rules {
		if f.rules[i].Table == rule.Table && f.rules[i].Priority == rule.Priority && sameDst(f.rules[i].Dst, rule.Dst) {
			return syscall.EEXIST
		}
	}
	f.rules = append(f.rules, *rule)
	return nil
}

func (f *fakeNetlink) RuleList(_ int) ([]netlink.Rule, error) { return slices.Clone(f.rules), nil }

func (f *fakeNetlink) RuleDel(rule *netlink.Rule) error {
	for i := range f.rules {
		if f.rules[i].Table == rule.Table && f.rules[i].Priority == rule.Priority && sameDst(f.rules[i].Dst, rule.Dst) {
			f.rules = slices.Delete(f.rules, i, i+1)
			return nil
		}
	}
	return syscall.ENOENT
}

func (f *fakeNetlink) routeDestinations(table int) []string {
	var destinations []string
	for _, route := range f.routes {
		if route.Table == table && route.Dst != nil {
			destinations = append(destinations, route.Dst.String())
		}
	}
	slices.Sort(destinations)
	return destinations
}

func (f *fakeNetlink) ruleDestinations(table, priority int) []string {
	var destinations []string
	for _, rule := range f.rules {
		if rule.Table == table && rule.Priority == priority && rule.Dst != nil {
			destinations = append(destinations, rule.Dst.String())
		}
	}
	slices.Sort(destinations)
	return destinations
}

func TestHostSNATLifecycle(t *testing.T) {
	ipt := &fakeIPTables{}
	manager := &netlinkRouteManager{
		linkName:    "flannel.mesh",
		clusterCIDR: "10.10.128.0/18",
		localCIDR:   "10.10.132.0/24",
		localSNATIP: "10.10.132.1",
		iptables:    ipt,
	}
	dst := mustCIDR(t, "10.10.135.0/24")
	want := []string{
		"!", "-s", "10.10.128.0/18",
		"-d", "10.10.135.0/24",
		"-m", "addrtype", "--src-type", "LOCAL",
		"-o", "flannel.mesh",
		"-m", "comment", "--comment", hostSNATComment,
		"-j", "SNAT", "--to-source", "10.10.132.1",
	}
	if err := manager.ensureHostSNAT(dst); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ipt.inserted, want) {
		t.Fatalf("unexpected inserted rule: %#v", ipt.inserted)
	}
	if err := manager.ensureHostSNAT(dst); err != nil {
		t.Fatal(err)
	}
	if err := manager.removeHostSNAT(dst); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ipt.deleted, want) {
		t.Fatalf("unexpected deleted rule: %#v", ipt.deleted)
	}
}

// newTestRouteManager returns a manager wired to fakes, with the Mesh CIDR
// route already in place the way newLocalRouteManager leaves it.
func newTestRouteManager(t *testing.T) (*netlinkRouteManager, *fakeNetlink, *fakeIPTables) {
	t.Helper()
	nl := &fakeNetlink{link: &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "flannel.mesh", Index: 7, MTU: 1280}}}
	ipt := &fakeIPTables{}
	manager := &netlinkRouteManager{
		linkName:    "flannel.mesh",
		meshIP:      net.ParseIP("100.96.1.2").To4(),
		mtu:         1280,
		table:       51820,
		meshCIDR:    "100.96.0.0/12",
		clusterCIDR: "10.10.128.0/18",
		localCIDR:   "10.10.132.0/24",
		localSNATIP: "10.10.132.1",
		iptables:    ipt,
		nl:          nl,
	}
	if err := manager.ensureMeshRoute(nl.link, mustCIDR(t, "100.96.0.0/12")); err != nil {
		t.Fatal(err)
	}
	return manager, nl, ipt
}

func TestReconcilePrunesLeasesLostWhileDown(t *testing.T) {
	manager, nl, ipt := newTestRouteManager(t)
	for _, network := range []string{"10.10.133.0/24", "10.10.134.0/24"} {
		if err := manager.Ensure(network); err != nil {
			t.Fatal(err)
		}
	}

	// 10.10.134.0/24 lost its lease while flanneld was down, so it never
	// produces a removal event.
	desired := map[string]struct{}{"10.10.133.0/24": {}}
	if err := manager.Reconcile(desired); err != nil {
		t.Fatal(err)
	}

	if got, want := nl.routeDestinations(51820), []string{"10.10.133.0/24", "100.96.0.0/12"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("routes after reconcile = %v, want %v", got, want)
	}
	if got, want := nl.ruleDestinations(51820, remoteRulePriority), []string{"10.10.133.0/24"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("policy rules after reconcile = %v, want %v", got, want)
	}
	if got, want := nl.ruleDestinations(51820, meshRulePriority), []string{"100.96.0.0/12"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Mesh CIDR rule after reconcile = %v, want %v", got, want)
	}
	snat, err := manager.managedSNATDestinations()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.10.133.0/24"}; !reflect.DeepEqual(snat, want) {
		t.Fatalf("SNAT rules after reconcile = %v, want %v", snat, want)
	}
	if len(ipt.rules) != 1 {
		t.Fatalf("expected exactly one SNAT rule to survive, got %d", len(ipt.rules))
	}
}

func TestReconcileIsIdempotent(t *testing.T) {
	manager, nl, ipt := newTestRouteManager(t)
	desired := map[string]struct{}{"10.10.133.0/24": {}}
	for range 3 {
		if err := manager.Reconcile(desired); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(nl.routes); got != 2 {
		t.Fatalf("route count = %d, want 2", got)
	}
	if got := len(nl.rules); got != 2 {
		t.Fatalf("policy rule count = %d, want 2", got)
	}
	if got := len(ipt.rules); got != 1 {
		t.Fatalf("SNAT rule count = %d, want 1", got)
	}
}

// A crash between the three deletions in Remove leaves partial state, which
// only the independent per-resource scan in staleDestinations can find.
func TestReconcilePrunesOrphanedSNATRule(t *testing.T) {
	manager, _, ipt := newTestRouteManager(t)
	if err := manager.ensureHostSNAT(mustCIDR(t, "10.10.134.0/24")); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reconcile(nil); err != nil {
		t.Fatal(err)
	}
	if len(ipt.rules) != 0 {
		t.Fatalf("orphaned SNAT rule survived reconcile: %v", ipt.rules)
	}
}

func TestCleanupRemovesEverything(t *testing.T) {
	manager, nl, ipt := newTestRouteManager(t)
	for _, network := range []string{"10.10.133.0/24", "10.10.134.0/24"} {
		if err := manager.Ensure(network); err != nil {
			t.Fatal(err)
		}
	}
	// A rule belonging to another subsystem must survive teardown.
	unrelated := netlink.NewRule()
	unrelated.Priority = 32766
	unrelated.Table = 254
	if err := nl.RuleAdd(unrelated); err != nil {
		t.Fatal(err)
	}

	if err := manager.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if got := nl.routeDestinations(51820); got != nil {
		t.Fatalf("routes survived cleanup: %v", got)
	}
	if len(ipt.rules) != 0 {
		t.Fatalf("SNAT rules survived cleanup: %v", ipt.rules)
	}
	if len(nl.rules) != 1 || nl.rules[0].Priority != 32766 {
		t.Fatalf("cleanup did not leave exactly the unrelated rule: %v", nl.rules)
	}
}

// Teardown runs after the transport has already destroyed the TUN device, so
// Cleanup must not depend on being able to look the link up.
func TestCleanupWorksWithoutTheMeshLink(t *testing.T) {
	manager, nl, _ := newTestRouteManager(t)
	if err := manager.Ensure("10.10.133.0/24"); err != nil {
		t.Fatal(err)
	}
	nl.link = nil
	if err := manager.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if got := nl.routeDestinations(51820); got != nil {
		t.Fatalf("routes survived cleanup: %v", got)
	}
}

func TestSNATDestinations(t *testing.T) {
	rules := []string{
		"-N FLANNEL-POSTRTG",
		"-A FLANNEL-POSTRTG -m mark --mark 0x4000/0x4000 -m comment --comment \"flanneld masq\" -j RETURN",
		"-A FLANNEL-POSTRTG ! -s 10.10.128.0/18 -d 10.10.133.0/24 -m addrtype --src-type LOCAL -o flannel.mesh" +
			" -m comment --comment \"" + hostSNATComment + "\" -j SNAT --to-source 10.10.132.1",
		"-A FLANNEL-POSTRTG ! -s 10.10.128.0/18 -d 10.10.134.0/24 -m addrtype --src-type LOCAL -o flannel.mesh" +
			" -m comment --comment \"" + hostSNATComment + "\" -j SNAT --to-source 10.10.132.1",
	}
	want := []string{"10.10.133.0/24", "10.10.134.0/24"}
	if got := snatDestinations(rules); !reflect.DeepEqual(got, want) {
		t.Fatalf("snatDestinations = %v, want %v", got, want)
	}
}

func TestCIDRsOverlap(t *testing.T) {
	for name, tc := range map[string]struct {
		first, second string
		want          bool
	}{
		"disjoint":  {"100.96.0.0/12", "10.10.128.0/18", false},
		"contained": {"100.96.0.0/12", "100.100.0.0/16", true},
		"identical": {"10.10.128.0/18", "10.10.128.0/18", true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := cidrsOverlap(mustCIDR(t, tc.first), mustCIDR(t, tc.second)); got != tc.want {
				t.Fatalf("cidrsOverlap(%s, %s) = %t, want %t", tc.first, tc.second, got, tc.want)
			}
		})
	}
}

func TestFirstUsableIPv4(t *testing.T) {
	ip, err := firstUsableIPv4(mustCIDR(t, "10.10.132.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ip.String(), "10.10.132.1"; got != want {
		t.Fatalf("first usable address = %s, want %s", got, want)
	}
	if _, err := firstUsableIPv4(mustCIDR(t, "10.10.132.7/32")); err == nil {
		t.Fatal("expected /32 to have no usable gateway")
	}
}

func mustCIDR(t *testing.T, value string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		t.Fatal(err)
	}
	return network
}
