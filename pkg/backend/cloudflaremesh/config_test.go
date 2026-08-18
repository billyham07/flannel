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
	"strings"
	"testing"
)

// quicMaxDatagramPayload reproduces the check quic-go makes before it accepts a
// datagram, so the test fails if quicDatagramOverhead ever stops covering it:
// estimateMaxPayloadSize subtracts the short header type byte, the largest
// connection ID and the AEAD tag from the packet size, and the DATAGRAM frame
// costs its type byte plus a two-byte length varint on top of that.
func quicMaxDatagramPayload(packetSize int) int {
	return packetSize - 1 - 20 - 16 - 1 - 2
}

func TestQUICInitialPacketSizeCarriesAFullMTUPacket(t *testing.T) {
	for _, mtu := range []int{1280, 1300, 1400, 1407} {
		// The datagram is the IP packet plus the CONNECT-IP context ID and the
		// HTTP/3 quarter-stream ID.
		datagram := mtu + tunHeadroom + 1
		if got := quicMaxDatagramPayload(int(quicInitialPacketSize(mtu))); got < datagram {
			t.Errorf("MTU %d: a session starts at %d bytes, which carries a %d byte datagram, but a full packet needs %d",
				mtu, quicInitialPacketSize(mtu), got, datagram)
		}
	}
}

func TestQUICInitialPacketSizeStaysWithinQUICsLimit(t *testing.T) {
	if got := quicInitialPacketSize(maxQUICPacketSize); got != maxQUICPacketSize {
		t.Errorf("initial packet size %d exceeds the largest packet quic-go sends (%d)", got, maxQUICPacketSize)
	}
}

func TestLoadConfigRejectsAnMTUNoDatagramCanCarry(t *testing.T) {
	tooBig := maxQUICPacketSize - quicDatagramOverhead + 1
	raw, err := json.Marshal(config{InterfaceName: "flannel.mesh", MeshCIDR: defaultMeshCIDR, RouteTable: 1, MTU: tooBig})
	if err != nil {
		t.Fatal(err)
	}
	_, err = loadConfig(raw)
	if err == nil {
		t.Fatalf("MTU %d was accepted, but no CONNECT-IP datagram can carry it", tooBig)
	}
	if !strings.Contains(err.Error(), "MTU must be at most") {
		t.Fatalf("unexpected error for MTU %d: %v", tooBig, err)
	}
}

func TestLoadConfigAcceptsTheLargestCarriableMTU(t *testing.T) {
	largest := maxQUICPacketSize - quicDatagramOverhead
	raw, err := json.Marshal(config{InterfaceName: "flannel.mesh", MeshCIDR: defaultMeshCIDR, RouteTable: 1, MTU: largest, NodeName: "node"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(raw)
	if err != nil {
		t.Fatalf("MTU %d was rejected: %v", largest, err)
	}
	if cfg.MTU != largest {
		t.Fatalf("MTU = %d, want %d", cfg.MTU, largest)
	}
}
