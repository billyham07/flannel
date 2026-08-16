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
	"testing"
	"time"
)

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
