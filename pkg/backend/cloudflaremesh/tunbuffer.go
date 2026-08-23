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
	"errors"
	"fmt"
)

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

	// tunWriteOffset is the Linux virtio-net header space required by
	// wireguard/tun when CreateTUN enables IFF_VNET_HDR. CONNECT-IP's receive
	// API returns a zero-copy packet without that headroom, so each receive
	// pump copies into one reusable scratch buffer. This keeps singleton writes
	// allocation-free; batching them would extend the lifetime of HTTP/3's
	// receive buffer and require additional packet copies.
	tunWriteOffset = 10
)

// tunBufferPoolSizeForBatch leaves one complete Device.Read batch outside the
// outbound queue, plus slack for the MASQUE writer and shutdown handoff. If the
// batch weren't included, a full outbound queue could starve the next batch
// acquisition before the writer is able to return a buffer.
func tunBufferPoolSizeForBatch(batchSize int) int {
	if batchSize < 1 {
		batchSize = 1
	}
	return outboundQueueDepth + batchSize + 32
}

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

// tunBatchReader is the narrow part of tun.Device used by the egress pump. It
// keeps the ownership and cancellation behavior independently testable without
// requiring a privileged Linux TUN device.
type tunBatchReader interface {
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
}

type tunBatchWriter interface {
	Write(bufs [][]byte, offset int) (int, error)
}

type tunPacketWriter struct {
	device  tunBatchWriter
	bufs    [][]byte
	scratch []byte
	stats   *transportStats
}

func newTUNPacketWriter(device tunBatchWriter, mtu int, stats *transportStats) *tunPacketWriter {
	scratch := make([]byte, tunWriteOffset+mtu)
	return &tunPacketWriter{device: device, bufs: [][]byte{scratch}, scratch: scratch, stats: stats}
}

func (w *tunPacketWriter) write(packet []byte) error {
	if len(packet) > len(w.scratch)-tunWriteOffset {
		return fmt.Errorf("TUN write packet length %d exceeds MTU buffer %d", len(packet), len(w.scratch)-tunWriteOffset)
	}
	copy(w.scratch[tunWriteOffset:], packet)
	w.bufs[0] = w.scratch[:tunWriteOffset+len(packet)]
	if w.stats != nil {
		w.stats.tunWriteCalls.Add(1)
	}
	_, err := w.device.Write(w.bufs, tunWriteOffset)
	if err == nil && w.stats != nil {
		w.stats.tunWritePackets.Add(1)
	}
	return err
}

// pumpTUNToOutbound moves ownership of every successfully read buffer to the
// outbound queue. All buffers that weren't returned as packets, and every
// buffer on an error/cancellation path, are returned to the bounded pool.
func pumpTUNToOutbound(ctx context.Context, reader tunBatchReader, batchSize int, pool *tunBufferPool, outbound chan<- []byte, stats *transportStats) error {
	if batchSize < 1 {
		return errors.New("TUN batch size must be positive")
	}
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for {
		acquired := 0
		for acquired < batchSize {
			buf, ok := pool.get(ctx)
			if !ok {
				for i := 0; i < acquired; i++ {
					pool.put(bufs[i])
				}
				return context.Cause(ctx)
			}
			bufs[acquired] = buf
			sizes[acquired] = 0
			acquired++
		}

		if stats != nil {
			stats.tunReadCalls.Add(1)
		}
		n, err := reader.Read(bufs, sizes, tunHeadroom)
		if err != nil {
			for i := range bufs {
				pool.put(bufs[i])
			}
			return err
		}
		if n < 1 || n > batchSize {
			for i := range bufs {
				pool.put(bufs[i])
			}
			return fmt.Errorf("TUN read returned invalid packet count %d for batch size %d", n, batchSize)
		}
		for i := n; i < batchSize; i++ {
			pool.put(bufs[i])
		}
		for i := 0; i < n; i++ {
			if sizes[i] < 1 || sizes[i] > len(bufs[i])-tunHeadroom {
				for j := 0; j < n; j++ {
					pool.put(bufs[j])
				}
				return fmt.Errorf("TUN read returned invalid packet size %d at batch index %d", sizes[i], i)
			}
		}
		if stats != nil {
			stats.tunReadPackets.Add(uint64(n))
		}
		for i := 0; i < n; i++ {
			packet := bufs[i][:tunHeadroom+sizes[i]]
			if !enqueueOutbound(ctx, outbound, packet, stats) {
				for j := i; j < n; j++ {
					pool.put(bufs[j])
				}
				return context.Cause(ctx)
			}
		}
	}
}
