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
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// activeTransportStats is read by the diagnostics HTTP handler. There is only
// one cloudflare-mesh backend per flanneld process, but CompareAndSwap on
// teardown keeps an old transport from clearing a replacement's counters.
var activeTransportStats atomic.Pointer[transportStats]

// transportStats contains only atomic values on the packet hot path. A
// snapshot can therefore be taken without stopping either dataplane pump.
type transportStats struct {
	txPackets atomic.Uint64
	txBytes   atomic.Uint64
	rxPackets atomic.Uint64
	rxBytes   atomic.Uint64

	outboundQueueDepth     atomic.Uint64
	outboundQueueHighWater atomic.Uint64
	outboundQueueWaits     atomic.Uint64
	poolExhaustions        atomic.Uint64
	icmpTooLarge           atomic.Uint64

	sessionsStarted   atomic.Uint64
	sessionsConnected atomic.Uint64
	sessionErrors     atomic.Uint64
	reconnects        atomic.Uint64
	sessionActive     atomic.Bool

	quicConn atomic.Pointer[quic.Conn]

	internalMu    sync.RWMutex
	internalDrops internalDropStatsProvider
}

// internalDropStatsProvider keeps dependency-specific queue reads separate
// from the application counters. Between sessions the provider is absent, so
// snapshots report the values as unavailable, never as zero.
type internalDropStatsProvider interface {
	InternalDropStats() internalDropStats
}

type internalDropStats struct {
	QUICReceiveQueueDrops     *uint64
	QUICReceiveQueueHighWater *uint64
	QUICReceiveQueueCapacity  *uint64
	HTTP3DatagramDrops        *uint64
	HTTP3DatagramHighWater    *uint64
	HTTP3DatagramCapacity     *uint64
}

func (s *transportStats) setInternalDropStatsProvider(provider internalDropStatsProvider) {
	s.internalMu.Lock()
	s.internalDrops = provider
	s.internalMu.Unlock()
}

func (s *transportStats) clearInternalDropStatsProvider(provider internalDropStatsProvider) {
	s.internalMu.Lock()
	if s.internalDrops == provider {
		s.internalDrops = nil
	}
	s.internalMu.Unlock()
}

type quicHTTP3DropStatsProvider struct {
	quic  *quic.Conn
	http3 *http3.ClientConn
}

func uint64Pointer(value uint64) *uint64 { return &value }

func (p *quicHTTP3DropStatsProvider) InternalDropStats() internalDropStats {
	quicStats := p.quic.DatagramReceiveQueueStats()
	http3Stats := p.http3.DatagramReceiveQueueStats()
	return internalDropStats{
		QUICReceiveQueueDrops:     uint64Pointer(quicStats.Dropped),
		QUICReceiveQueueHighWater: uint64Pointer(quicStats.HighWater),
		QUICReceiveQueueCapacity:  uint64Pointer(quicStats.Capacity),
		HTTP3DatagramDrops:        uint64Pointer(http3Stats.Dropped),
		HTTP3DatagramHighWater:    uint64Pointer(http3Stats.HighWater),
		HTTP3DatagramCapacity:     uint64Pointer(http3Stats.CapacityPerStream),
	}
}

func (s *transportStats) setQUICConn(conn *quic.Conn) { s.quicConn.Store(conn) }

func (s *transportStats) clearQUICConn(conn *quic.Conn) {
	s.quicConn.CompareAndSwap(conn, nil)
}

func (s *transportStats) observeOutboundDepth(depth int) {
	value := uint64(depth)
	s.outboundQueueDepth.Store(value)
	for current := s.outboundQueueHighWater.Load(); value > current; current = s.outboundQueueHighWater.Load() {
		if s.outboundQueueHighWater.CompareAndSwap(current, value) {
			break
		}
	}
}

type transportStatsSnapshot struct {
	Dataplane dataplaneStatsSnapshot `json:"dataplane"`
	Sessions  sessionStatsSnapshot   `json:"sessions"`
	QUIC      quicStatsSnapshot      `json:"quic"`
	Drops     internalDropsSnapshot  `json:"internal_drops"`
}

type dataplaneStatsSnapshot struct {
	TXPackets              uint64 `json:"tx_packets"`
	TXBytes                uint64 `json:"tx_bytes"`
	RXPackets              uint64 `json:"rx_packets"`
	RXBytes                uint64 `json:"rx_bytes"`
	OutboundQueueDepth     uint64 `json:"outbound_queue_depth"`
	OutboundQueueHighWater uint64 `json:"outbound_queue_high_water"`
	OutboundQueueWaits     uint64 `json:"outbound_queue_waits"`
	PoolExhaustions        uint64 `json:"buffer_pool_exhaustions"`
	ICMPTooLarge           uint64 `json:"icmp_too_large"`
}

type sessionStatsSnapshot struct {
	Started    uint64 `json:"started"`
	Connected  uint64 `json:"connected"`
	Errors     uint64 `json:"errors"`
	Reconnects uint64 `json:"reconnects"`
	Active     bool   `json:"active"`
}

type quicStatsSnapshot struct {
	Available           bool          `json:"available"`
	GSO                 bool          `json:"gso"`
	MinRTT              time.Duration `json:"min_rtt_ns"`
	LatestRTT           time.Duration `json:"latest_rtt_ns"`
	SmoothedRTT         time.Duration `json:"smoothed_rtt_ns"`
	MeanDeviation       time.Duration `json:"mean_deviation_ns"`
	BytesSent           uint64        `json:"bytes_sent"`
	PacketsSent         uint64        `json:"packets_sent"`
	BytesReceived       uint64        `json:"bytes_received"`
	PacketsReceived     uint64        `json:"packets_received"`
	BytesLost           uint64        `json:"bytes_lost"`
	PacketsLost         uint64        `json:"packets_lost"`
	GSOBatches          uint64        `json:"gso_batches"`
	GSOSegments         uint64        `json:"gso_segments"`
	GSOSegmentsPerBatch float64       `json:"gso_segments_per_batch"`
}

type internalDropsSnapshot struct {
	Available                 bool    `json:"available"`
	QUICReceiveQueueDrops     *uint64 `json:"quic_receive_queue_drops"`
	QUICReceiveQueueHighWater *uint64 `json:"quic_receive_queue_high_water"`
	QUICReceiveQueueCapacity  *uint64 `json:"quic_receive_queue_capacity"`
	HTTP3DatagramDrops        *uint64 `json:"http3_datagram_queue_drops"`
	HTTP3DatagramHighWater    *uint64 `json:"http3_datagram_queue_high_water"`
	HTTP3DatagramCapacity     *uint64 `json:"http3_datagram_queue_capacity_per_stream"`
	Reason                    string  `json:"reason,omitempty"`
}

func (s *transportStats) snapshot() transportStatsSnapshot {
	snapshot := transportStatsSnapshot{
		Dataplane: dataplaneStatsSnapshot{
			TXPackets: s.txPackets.Load(), TXBytes: s.txBytes.Load(),
			RXPackets: s.rxPackets.Load(), RXBytes: s.rxBytes.Load(),
			OutboundQueueDepth:     s.outboundQueueDepth.Load(),
			OutboundQueueHighWater: s.outboundQueueHighWater.Load(),
			OutboundQueueWaits:     s.outboundQueueWaits.Load(),
			PoolExhaustions:        s.poolExhaustions.Load(), ICMPTooLarge: s.icmpTooLarge.Load(),
		},
		Sessions: sessionStatsSnapshot{
			Started: s.sessionsStarted.Load(), Connected: s.sessionsConnected.Load(),
			Errors: s.sessionErrors.Load(), Reconnects: s.reconnects.Load(), Active: s.sessionActive.Load(),
		},
		Drops: internalDropsSnapshot{
			Reason: "no active QUIC/HTTP3 session",
		},
	}
	if conn := s.quicConn.Load(); conn != nil {
		stats := conn.ConnectionStats()
		segmentsPerBatch := float64(0)
		if stats.GSOBatches != 0 {
			segmentsPerBatch = float64(stats.GSOSegments) / float64(stats.GSOBatches)
		}
		snapshot.QUIC = quicStatsSnapshot{
			Available: true, GSO: conn.ConnectionState().GSO,
			MinRTT: stats.MinRTT, LatestRTT: stats.LatestRTT,
			SmoothedRTT: stats.SmoothedRTT, MeanDeviation: stats.MeanDeviation,
			BytesSent: stats.BytesSent, PacketsSent: stats.PacketsSent,
			BytesReceived: stats.BytesReceived, PacketsReceived: stats.PacketsReceived,
			BytesLost: stats.BytesLost, PacketsLost: stats.PacketsLost,
			GSOBatches: stats.GSOBatches, GSOSegments: stats.GSOSegments,
			GSOSegmentsPerBatch: segmentsPerBatch,
		}
	}
	s.internalMu.RLock()
	provider := s.internalDrops
	s.internalMu.RUnlock()
	if provider != nil {
		drops := provider.InternalDropStats()
		snapshot.Drops = internalDropsSnapshot{
			Available:                 drops.QUICReceiveQueueDrops != nil || drops.HTTP3DatagramDrops != nil,
			QUICReceiveQueueDrops:     drops.QUICReceiveQueueDrops,
			QUICReceiveQueueHighWater: drops.QUICReceiveQueueHighWater,
			QUICReceiveQueueCapacity:  drops.QUICReceiveQueueCapacity,
			HTTP3DatagramDrops:        drops.HTTP3DatagramDrops,
			HTTP3DatagramHighWater:    drops.HTTP3DatagramHighWater,
			HTTP3DatagramCapacity:     drops.HTTP3DatagramCapacity,
		}
	}
	return snapshot
}
