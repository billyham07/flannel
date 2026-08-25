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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

type fixedInternalDrops struct{ stats internalDropStats }

func (d fixedInternalDrops) InternalDropStats() internalDropStats { return d.stats }

func TestTransportStatsSnapshotDoesNotInventInternalDrops(t *testing.T) {
	stats := &transportStats{}
	stats.txPackets.Add(7)
	stats.txBytes.Add(700)
	stats.rxPackets.Add(5)
	stats.rxBytes.Add(450)
	stats.outboundQueueWaits.Add(2)
	stats.poolExhaustions.Add(1)
	stats.icmpTooLarge.Add(3)
	stats.tunReadCalls.Add(3)
	stats.tunReadPackets.Add(8)
	stats.tunWriteCalls.Add(5)
	stats.tunWritePackets.Add(5)
	stats.sessionsStarted.Add(4)
	stats.sessionsConnected.Add(3)
	stats.sessionErrors.Add(2)
	stats.reconnects.Add(3)
	stats.sessionActive.Store(true)
	stats.observeOutboundDepth(11)
	stats.observeOutboundDepth(4)

	snapshot := stats.snapshot()
	if snapshot.Dataplane.TXPackets != 7 || snapshot.Dataplane.TXBytes != 700 ||
		snapshot.Dataplane.RXPackets != 5 || snapshot.Dataplane.RXBytes != 450 {
		t.Fatalf("unexpected dataplane snapshot: %+v", snapshot.Dataplane)
	}
	if snapshot.Dataplane.OutboundQueueDepth != 4 || snapshot.Dataplane.OutboundQueueHighWater != 11 {
		t.Fatalf("unexpected outbound queue gauges: %+v", snapshot.Dataplane)
	}
	if snapshot.Dataplane.TUNReadCalls != 3 || snapshot.Dataplane.TUNReadPackets != 8 ||
		snapshot.Dataplane.TUNReadPacketsPerCall != float64(8)/3 ||
		snapshot.Dataplane.TUNWriteCalls != 5 || snapshot.Dataplane.TUNWritePackets != 5 ||
		snapshot.Dataplane.TUNWritePacketsPerCall != 1 {
		t.Fatalf("unexpected TUN batch snapshot: %+v", snapshot.Dataplane)
	}
	if !snapshot.Sessions.Active || snapshot.Sessions.Reconnects != 3 || snapshot.QUIC.Available {
		t.Fatalf("unexpected session/QUIC snapshot: sessions=%+v quic=%+v", snapshot.Sessions, snapshot.QUIC)
	}
	if snapshot.Drops.Available || snapshot.Drops.QUICReceiveQueueDrops != nil || snapshot.Drops.HTTP3DatagramDrops != nil {
		t.Fatalf("unobservable dependency drops must be unavailable/null: %+v", snapshot.Drops)
	}
}

func TestTransportStatsInternalDropProvider(t *testing.T) {
	quicDrops, quicHighWater, quicCapacity := uint64(8), uint64(120), uint64(128)
	http3Drops, http3HighWater, http3Capacity := uint64(13), uint64(31), uint64(32)
	stats := &transportStats{}
	stats.setInternalDropStatsProvider(fixedInternalDrops{internalDropStats{
		QUICReceiveQueueDrops:     &quicDrops,
		QUICReceiveQueueHighWater: &quicHighWater,
		QUICReceiveQueueCapacity:  &quicCapacity,
		HTTP3DatagramDrops:        &http3Drops,
		HTTP3DatagramHighWater:    &http3HighWater,
		HTTP3DatagramCapacity:     &http3Capacity,
	}})
	snapshot := stats.snapshot().Drops
	if !snapshot.Available || snapshot.QUICReceiveQueueDrops == nil || *snapshot.QUICReceiveQueueDrops != 8 ||
		snapshot.QUICReceiveQueueHighWater == nil || *snapshot.QUICReceiveQueueHighWater != 120 ||
		snapshot.QUICReceiveQueueCapacity == nil || *snapshot.QUICReceiveQueueCapacity != 128 ||
		snapshot.HTTP3DatagramDrops == nil || *snapshot.HTTP3DatagramDrops != 13 ||
		snapshot.HTTP3DatagramHighWater == nil || *snapshot.HTTP3DatagramHighWater != 31 ||
		snapshot.HTTP3DatagramCapacity == nil || *snapshot.HTTP3DatagramCapacity != 32 {
		t.Fatalf("patched dependency stats were not surfaced: %+v", snapshot)
	}
}

func TestTransportStatsInternalDropProviderClearsOnlyItself(t *testing.T) {
	first := &fixedInternalDrops{}
	second := &fixedInternalDrops{}
	stats := &transportStats{}
	stats.setInternalDropStatsProvider(first)
	stats.setInternalDropStatsProvider(second)
	stats.clearInternalDropStatsProvider(first)
	if stats.internalDrops != second {
		t.Fatal("an old session cleared the replacement session's internal stats")
	}
	stats.clearInternalDropStatsProvider(second)
	if stats.internalDrops != nil {
		t.Fatal("active internal stats provider was not cleared")
	}
}

func TestCloudflareMeshStatsHandler(t *testing.T) {
	stats := &transportStats{}
	stats.txPackets.Store(9)
	previous := activeTransportStats.Swap(stats)
	t.Cleanup(func() { activeTransportStats.Store(previous) })

	recorder := httptest.NewRecorder()
	cloudflareMeshStatsHandler(recorder, httptest.NewRequest(http.MethodGet, "/debug/cloudflare-mesh/stats", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", recorder.Code)
	}
	var snapshot transportStatsSnapshot
	if err := json.Unmarshal(recorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Dataplane.TXPackets != 9 {
		t.Fatalf("tx_packets = %d, want 9", snapshot.Dataplane.TXPackets)
	}
	if snapshot.Drops.QUICReceiveQueueDrops != nil || snapshot.Drops.HTTP3DatagramDrops != nil {
		t.Fatal("HTTP output must encode unavailable internal drops as null")
	}
}

func TestBufferPressureCounters(t *testing.T) {
	stats := &transportStats{}
	pool := newTUNBufferPoolWithStats(1, 1280, stats)
	if _, ok := pool.get(context.Background()); !ok {
		t.Fatal("expected first pool buffer")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := pool.get(cancelled); ok {
		t.Fatal("exhausted pool unexpectedly returned a buffer")
	}
	if stats.poolExhaustions.Load() != 1 {
		t.Fatalf("pool exhaustions = %d, want 1", stats.poolExhaustions.Load())
	}

	outbound := make(chan []byte, 1)
	outbound <- []byte{1}
	done := make(chan bool, 1)
	go func() { done <- enqueueOutbound(context.Background(), outbound, []byte{2}, stats) }()
	deadline := time.Now().Add(time.Second)
	for stats.outboundQueueWaits.Load() == 0 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if stats.outboundQueueWaits.Load() != 1 {
		t.Fatalf("queue waits = %d, want 1", stats.outboundQueueWaits.Load())
	}
	<-outbound
	if !<-done {
		t.Fatal("blocked enqueue did not complete")
	}
	if stats.outboundQueueHighWater.Load() != 1 {
		t.Fatalf("queue high-water = %d, want 1", stats.outboundQueueHighWater.Load())
	}
}
