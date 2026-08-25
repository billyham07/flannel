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

import "context"

const (
	// tunHeadroom reserves the one-byte CONNECT-IP context ID plus the largest
	// possible eight-byte HTTP/3 quarter stream ID. Both layers prepend their
	// framing into this slack, so neither allocates or copies the IP payload.
	// Only the bytes actually used for the stream ID are sent.
	tunHeadroom = 1 + 8

	// outboundQueueDepth is how many read packets may wait for the MASQUE
	// writer. It absorbs a stalled QUIC send without dropping traffic, and
	// bounds how far the TUN reader can run ahead.
	outboundQueueDepth = 256

	// tunBufferPoolSize must exceed outboundQueueDepth, otherwise the reader
	// could own the last free buffer while the queue holds all the others and
	// the writer is between sessions. The surplus covers the buffer in the
	// reader plus the one the writer is currently sending.
	tunBufferPoolSize = outboundQueueDepth + 32
)

// tunBufferPool is a bounded freelist of TUN read buffers.
//
// The transmit path used to allocate one buffer per packet, which at line rate
// is the dominant source of garbage in flanneld. The pool replaces that with a
// fixed set of buffers whose ownership moves in one direction, with exactly one
// stage owning a buffer at any time:
//
//	pool -> TUN reader -> outbound queue -> MASQUE writer -> pool
//
// Every buffer carries tunHeadroom bytes of slack at the front so the writer
// keeps the zero-copy WritePacketBuffer path.
type tunBufferPool struct {
	free  chan []byte
	size  int
	stats *transportStats
}

func newTUNBufferPool(count, mtu int) *tunBufferPool {
	return newTUNBufferPoolWithStats(count, mtu, nil)
}

func newTUNBufferPoolWithStats(count, mtu int, stats *transportStats) *tunBufferPool {
	pool := &tunBufferPool{
		free:  make(chan []byte, count),
		size:  mtu + tunHeadroom,
		stats: stats,
	}
	for i := 0; i < count; i++ {
		pool.free <- make([]byte, pool.size)
	}
	return pool
}

// get takes ownership of a buffer, blocking until one is returned or ctx is
// cancelled. The returned buffer is full length: the caller reads the packet
// into buf[tunHeadroom:] and reslices to the bytes it actually read.
func (p *tunBufferPool) get(ctx context.Context) ([]byte, bool) {
	select {
	case buf := <-p.free:
		return buf[:p.size], true
	default:
		if p.stats != nil {
			p.stats.poolExhaustions.Add(1)
		}
	}
	select {
	case buf := <-p.free:
		return buf[:p.size], true
	case <-ctx.Done():
		return nil, false
	}
}

// put hands a buffer back. The freelist has room for every buffer the pool
// created, so this never blocks; the non-blocking send only guards against a
// caller returning a buffer that did not come from here.
func (p *tunBufferPool) put(buf []byte) {
	if cap(buf) < p.size {
		return
	}
	select {
	case p.free <- buf[:p.size]:
	default:
	}
}

// enqueueOutbound records only actual contention. The fast path is one
// non-blocking channel send and atomics; if the queue is full, the reader
// blocks (preserving packets) and outboundQueueWaits identifies that pressure.
func enqueueOutbound(ctx context.Context, outbound chan<- []byte, buf []byte, stats *transportStats) bool {
	select {
	case outbound <- buf:
		if stats != nil {
			stats.observeOutboundDepth(len(outbound))
		}
		return true
	default:
		if stats != nil {
			stats.outboundQueueWaits.Add(1)
		}
	}
	select {
	case outbound <- buf:
		if stats != nil {
			stats.observeOutboundDepth(len(outbound))
		}
		return true
	case <-ctx.Done():
		return false
	}
}
