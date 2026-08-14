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
	"testing"
)

type fakeIPTables struct {
	exists   bool
	inserted []string
	deleted  []string
}

func (f *fakeIPTables) Exists(_, _ string, _ ...string) (bool, error) { return f.exists, nil }
func (f *fakeIPTables) Insert(_, _ string, _ int, rulespec ...string) error {
	f.inserted = append([]string(nil), rulespec...)
	f.exists = true
	return nil
}
func (f *fakeIPTables) Delete(_, _ string, rulespec ...string) error {
	f.deleted = append([]string(nil), rulespec...)
	f.exists = false
	return nil
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
