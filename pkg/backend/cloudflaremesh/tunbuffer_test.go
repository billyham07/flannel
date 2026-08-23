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
	"testing"
	"time"
)

type scriptedTUNReader struct {
	batches [][][]byte
	err     error
	calls   int
	called  chan struct{}
}

func (r *scriptedTUNReader) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	r.calls++
	if r.called != nil {
		select {
		case r.called <- struct{}{}:
		default:
		}
	}
	if len(r.batches) == 0 {
		return 0, r.err
	}
	batch := r.batches[0]
	r.batches = r.batches[1:]
	for i, packet := range batch {
		copy(bufs[i][offset:], packet)
		sizes[i] = len(packet)
	}
	return len(batch), nil
}

type recordingTUNWriter struct {
	offset int
	packet []byte
}

type discardTUNWriter struct{}

func (discardTUNWriter) Write(_ [][]byte, _ int) (int, error) { return 1, nil }

func (w *recordingTUNWriter) Write(bufs [][]byte, offset int) (int, error) {
	w.offset = offset
	w.packet = append(w.packet[:0], bufs[0][offset:]...)
	return 1, nil
}

func TestTUNBufferPoolReservesHeadroom(t *testing.T) {
	pool := newTUNBufferPool(2, 1280)
	buf, ok := pool.get(context.Background())
	if !ok {
		t.Fatal("a fresh pool must hand out a buffer")
	}
	if len(buf) != 1280+tunHeadroom {
		t.Fatalf("buffer length = %d, want %d", len(buf), 1280+tunHeadroom)
	}
	// The headroom is what keeps WritePacketBuffer on its zero-copy path: the
	// packet has to start far enough in for the context ID to be written in
	// place.
	packet := buf[tunHeadroom:]
	if len(packet) != 1280 {
		t.Fatalf("packet capacity = %d, want the full MTU", len(packet))
	}
}

// The pool exists so the transmit path stops allocating; if a returned buffer
// were not reused, the freelist would drain and the reader would deadlock.
func TestTUNBufferPoolRecyclesBuffers(t *testing.T) {
	pool := newTUNBufferPool(1, 1280)
	first, ok := pool.get(context.Background())
	if !ok {
		t.Fatal("expected a buffer")
	}
	pool.put(first[:16])
	second, ok := pool.get(context.Background())
	if !ok {
		t.Fatal("returned buffer was not reused")
	}
	if len(second) != 1280+tunHeadroom {
		t.Fatalf("recycled buffer was not restored to full length: %d", len(second))
	}
	if &second[0] != &first[0] {
		t.Fatal("expected the same backing array, not a fresh allocation")
	}
}

// An exhausted pool must block rather than allocate, and must still unblock
// when the transport shuts down -- otherwise Close would hang on the reader.
func TestTUNBufferPoolGetHonoursCancellation(t *testing.T) {
	pool := newTUNBufferPool(1, 1280)
	if _, ok := pool.get(context.Background()); !ok {
		t.Fatal("expected a buffer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, ok := pool.get(ctx); ok {
		t.Fatal("an empty pool must not hand out a buffer")
	}
}

// put is deliberately non-blocking, so a foreign buffer must be dropped
// instead of growing the freelist past the size the pool was built with.
func TestTUNBufferPoolRejectsForeignBuffers(t *testing.T) {
	pool := newTUNBufferPool(1, 1280)
	pool.put(make([]byte, 32))
	if len(pool.free) != 1 {
		t.Fatalf("freelist length = %d, want the pool's own single buffer", len(pool.free))
	}
}

// The whole point of the change: reading and forwarding packets must not
// allocate once the pool is warm.
func TestTUNBufferPoolTransmitLoopDoesNotAllocate(t *testing.T) {
	pool := newTUNBufferPool(4, 1280)
	ctx := context.Background()
	allocations := testing.AllocsPerRun(1000, func() {
		buf, ok := pool.get(ctx)
		if !ok {
			t.Fatal("expected a buffer")
		}
		pool.put(buf[:tunHeadroom+64])
	})
	if allocations != 0 {
		t.Fatalf("buffer round trip allocated %v times per packet, want 0", allocations)
	}
}

func TestTUNBufferPoolIncludesCompleteReadBatch(t *testing.T) {
	for _, batchSize := range []int{0, 1, 128} {
		wantBatch := batchSize
		if wantBatch < 1 {
			wantBatch = 1
		}
		want := outboundQueueDepth + wantBatch + 32
		if got := tunBufferPoolSizeForBatch(batchSize); got != want {
			t.Fatalf("batch size %d: pool size = %d, want %d", batchSize, got, want)
		}
	}
}

func TestPumpTUNToOutboundEnqueuesEveryPacketAndRecyclesUnusedBuffers(t *testing.T) {
	stopErr := errors.New("stop after first batch")
	reader := &scriptedTUNReader{
		batches: [][][]byte{{[]byte("first"), []byte("second"), []byte("third")}},
		err:     stopErr,
	}
	stats := &transportStats{}
	pool := newTUNBufferPoolWithStats(8, 1280, stats)
	outbound := make(chan []byte, 8)
	err := pumpTUNToOutbound(context.Background(), reader, 4, pool, outbound, stats)
	if !errors.Is(err, stopErr) {
		t.Fatalf("pump error = %v, want %v", err, stopErr)
	}
	if reader.calls != 2 {
		t.Fatalf("read calls = %d, want 2", reader.calls)
	}
	if stats.tunReadCalls.Load() != 2 || stats.tunReadPackets.Load() != 3 {
		t.Fatalf("TUN read counters = calls:%d packets:%d, want 2/3", stats.tunReadCalls.Load(), stats.tunReadPackets.Load())
	}
	if len(outbound) != 3 {
		t.Fatalf("outbound packets = %d, want 3", len(outbound))
	}
	for _, want := range []string{"first", "second", "third"} {
		packet := <-outbound
		if got := string(packet[tunHeadroom:]); got != want {
			t.Fatalf("packet = %q, want %q", got, want)
		}
		pool.put(packet)
	}
	if len(pool.free) != 8 {
		t.Fatalf("free buffers after recycling = %d, want 8", len(pool.free))
	}
}

func TestPumpTUNToOutboundCancellationReturnsUnqueuedBatch(t *testing.T) {
	reader := &scriptedTUNReader{batches: [][][]byte{{[]byte("one"), []byte("two")}}, called: make(chan struct{}, 1)}
	pool := newTUNBufferPool(4, 1280)
	outbound := make(chan []byte)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pumpTUNToOutbound(ctx, reader, 2, pool, outbound, nil) }()
	select {
	case <-reader.called:
	case <-time.After(time.Second):
		t.Fatal("TUN reader was not called")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("pump error = %v, want context canceled", err)
	}
	if len(pool.free) != 4 {
		t.Fatalf("free buffers after cancellation = %d, want 4", len(pool.free))
	}
}

func TestTUNPacketWriterUsesReusableVirtioHeadroom(t *testing.T) {
	device := &recordingTUNWriter{}
	stats := &transportStats{}
	writer := newTUNPacketWriter(device, 1280, stats)
	backing := &writer.scratch[0]
	if err := writer.write([]byte("packet-one")); err != nil {
		t.Fatal(err)
	}
	if device.offset != tunWriteOffset || string(device.packet) != "packet-one" {
		t.Fatalf("write offset/packet = %d/%q, want %d/packet-one", device.offset, device.packet, tunWriteOffset)
	}
	if err := writer.write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	if &writer.scratch[0] != backing {
		t.Fatal("TUN writer replaced its reusable scratch buffer")
	}
	if stats.tunWriteCalls.Load() != 2 || stats.tunWritePackets.Load() != 2 {
		t.Fatalf("TUN write counters = calls:%d packets:%d, want 2/2", stats.tunWriteCalls.Load(), stats.tunWritePackets.Load())
	}
}

func TestTUNPacketWriterDoesNotAllocatePerPacket(t *testing.T) {
	writer := newTUNPacketWriter(discardTUNWriter{}, 1280, nil)
	packet := make([]byte, 1280)
	allocations := testing.AllocsPerRun(1000, func() {
		if err := writer.write(packet); err != nil {
			t.Fatal(err)
		}
	})
	if allocations != 0 {
		t.Fatalf("TUN singleton write allocated %v times per packet, want 0", allocations)
	}
}
