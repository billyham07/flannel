# Cloudflare Mesh syscall profiling

This note captures the current performance evidence for the native MASQUE transport, what it turned out to explain, and what is still unmeasured.

## Baseline

A 60 second Mesh-IP to Mesh-IP iperf3 run after adding the bounded TUN buffer pool showed:

- throughput: 179 Mbit/s before and after
- retransmits: 15,150 -> 12,850
- flanneld CPU: 98.4% -> 94.7% of one core
- GC cycles: 20.9/s -> 13.3/s

The CPU profile after the buffer-pool change is dominated by syscall cost:

- sendmsg: 35.9%
- TUN write: 10.0%
- recvmsg: 6.7%
- scheduler: ~12%
- mallocgc: 3.2%
- GC scan: 1.9%
- AES-GCM: 1.0%

A differential allocation profile shows no flat allocation in `pkg/backend/cloudflaremesh`; most remaining allocation is quic-go taking ownership of datagrams.

## Why the baseline did not batch with UDP GSO

The upstream quic-go v0.60.0 path could not batch CONNECT-IP packets. This was a
structural property of how it packed and sent QUIC DATAGRAM frames.

- `packet_packer.go:654` takes **at most one** DATAGRAM frame per QUIC packet. It peeks
  the datagram queue once; there is no loop that fills the remaining payload.
- `connection.go:2633` only coalesces another packet into the same GSO batch when the
  packet just appended came out **exactly** `maxPacketSize` bytes long:

  ```go
  if !dontSendMore && size == maxSize && nextECN == ecn && buf.Len()+maxSize <= buf.Cap() {
  ```

A CONNECT-IP packet never satisfies that. At MTU 1280 the datagram is 1282 bytes (the IP
packet, the CONNECT-IP context ID and the HTTP/3 quarter-stream ID), the DATAGRAM frame
adds 3, and the short header plus AEAD tag add 18 to 41 depending on the connection ID
and packet number length -- 1303 to 1326 bytes against a
`maxPacketSize` that path MTU discovery pushes to 1452. The packet is always short of
`maxSize`, the loop always breaks, and every DATAGRAM leaves in its own `sendmsg`.

So `avg_packets_per_send` is 1.0 by construction, and the 35.9% is one `sendmsg` per pod
packet. Note this is a send-side-only problem: quic-go already reads with `recvmmsg` in
batches of 8 (`sys_conn_helper_linux.go:24`), which is why `recvmsg` is only 6.7%.

Measured on wmhknodel5, `strace -c -f` over a 15 second single-stream transfer that moved
181 MBytes, which is about 153,000 packets at the 1240 byte MSS:

```
% time     seconds  usecs/call     calls    errors syscall
 39.98    3.181900          20    155063           sendmsg
 30.43    2.421904          15    159440      4224 read
 20.58    1.638237          21     76799           write
  8.90    0.708555          17     39571     10534 recvmmsg
  0.10    0.008175           4      1745           recvmsg
```

155,063 `sendmsg` for ~153,000 packets is 1.01 per packet, and `sendmmsg` was never called
at all. The host's `Udp: OutDatagrams` counter agrees: 477,475 sends against ~484,500
packets over a separate 30 second run. `recvmmsg` doing the receive side in 39,571 calls is
the contrast.

The pinned quic-go fork now coalesces consecutive packets of *equal* wire size rather
than only full-size packets. Each batch locks onto its first data-sized packet, constrains
later packets to that size, preserves ECN boundaries, and permits only the last segment to
be shorter, as required by `UDP_SEGMENT`. Tiny ACK-only packets stay on the original
single-packet path. The fork also counts successful GSO writes and segments, so
`gso_segments / gso_batches` measures the result without wrapping `*net.UDPConn`.

Padding datagrams to `maxPacketSize` in flannel remains invalid: QUIC packet-number length
changes underneath the application, so the target wire size moves.

### Gray result: keep GSO opt-in

The old single-node cluster exposed a downstream tradeoff that the syscall profile alone
could not predict. The test sent 120 Mbit/s of 1252-byte UDP payloads for 60 seconds from
`100.96.0.23` to `100.96.0.38`, at MTU 1280. Receiver results and flanneld CPU are:

| sender | receiver throughput | receiver loss | flanneld CPU |
| --- | ---: | ---: | ---: |
| digest-pinned baseline, median of 3 | 116.41 Mbit/s | 2.95% | 33.81 s in a measured run |
| unrestricted equal-size GSO, median of 2 | 92.84 Mbit/s | 22.60% | 19.89 s |
| GSO capped at 4 segments, median of 3 | 106.02 Mbit/s | 11.63% | 22.04 s |

The capped fork did reduce CPU by about 35%, and its live counters showed an average of
3.44 segments per GSO write. However, it still reduced delivered throughput by about 9%
and added about 8.7 percentage points of receiver loss. Application, QUIC receive, and
HTTP/3 receive queues recorded no drops, buffer-pool exhaustion remained zero, and QUIC
reported only the two packets lost during startup. The evidence therefore points to the
on-wire burst interacting badly with this public path rather than a userspace queue limit.

The environment-specific Helm values set `QUIC_GO_DISABLE_GSO=true`. GSO is retained as
an explicit experiment, with the four-segment safety cap and counters, but is not the
production default. Removing that environment variable requires a path-specific gray test;
CPU improvement alone is not a promotion criterion.

## The MTU and the QUIC packet size were unrelated numbers

Chasing the size arithmetic above turned up a defect rather than an optimisation.

quic-go starts every connection at `InitialPacketSize` (1280 by default) and refuses a
datagram that does not fit the current packet size. It only grows through path MTU
discovery, five RTTs per probe. A 1280 byte pod packet needs a QUIC packet of at least
1325 bytes, so until discovery lifts the estimate, **every full-size pod packet is
rejected**.

The rejection is invisible. connect-ip-go answers `DatagramTooLargeError` by composing an
ICMP "fragmentation needed" quoting its `minMTU` of 1280, which is already the TUN MTU, so
the sender has nothing to shrink and simply retransmits. On a path whose MTU never reaches
1325 this is permanent: small packets flow, large packets black-hole, TCP hangs.

The fix is to derive one number from the other. `quicInitialPacketSize` now sizes the
session from the configured MTU (`config.go`), and `loadConfig` rejects an MTU larger than
any CONNECT-IP datagram can carry. Path MTU discovery still runs on top and can grow the
packet further.

This is worth re-running the benchmark against: some fraction of the 12,850 retransmits
may be full-size packets discarded during the discovery window at the start of the session,
and there is one such window per reconnect.

## flanneld is not the bottleneck

The ~179 Mbit/s ceiling is per peer pair, and it is the Cloudflare path, not this
dataplane. Measured on the five-node cluster, 30 second iperf3 runs between Mesh IPs,
receiver-side figures:

| test | what runs | result |
| --- | --- | --- |
| one stream, HK->HK | baseline | 147 Mbit/s |
| eight streams, HK->HK | is one stream loss-limited? | 155 Mbit/s |
| eight streams, JP->SYD | second pair alone | 151 Mbit/s |
| both pairs at once | two independent sessions | 154 + 149 Mbit/s |
| HK->HK and HK->SYD, from one node | one flanneld, one MASQUE session | 149 + 154 = **303** Mbit/s |
| three destinations, from one node | same | 125 + 161 + 148 = **434** Mbit/s |

Eight streams barely beat one, so the per-pair number is not inner-TCP loss. Two separate
node pairs do not contend, so it is not an account-wide limit. But one node fanning out to
three peers gets 434 Mbit/s through a **single** flanneld and a **single** QUIC connection
-- about three times what any one peer pair will give it.

So the transport has at least 3x headroom over what a single peer can use. Syscall batching
would buy CPU, not throughput.

CPU is still worth buying. At 434 Mbit/s flanneld cost 118% of one core, on a node that has
two cores in total -- roughly a quarter of a core per 100 Mbit/s. On small nodes that is the
real constraint, and it is what the `sendmsg`-per-packet result above translates into.

## Receive-queue pressure is now measurable

There are two bounded receive queues, not one: quic-go first buffers 128 QUIC DATAGRAMs,
then HTTP/3 buffers only 32 datagrams per request stream. Both previously discarded
silently when full, so the HTTP/3 queue could hide loss before the QUIC queue reached its
limit. The pinned fork exposes cumulative drop, high-water, and capacity values for both
layers. flannel publishes them together with application queue pressure, RTT, QUIC loss,
and session counters at `http://127.0.0.1:6060/debug/cloudflare-mesh/stats` when the
loopback diagnostics listener is enabled.

Correlate these counters against inner TCP retransmits and UDP loss. A drop counter of
zero is meaningful only while `internal_drops.available` is true; between sessions the
fields are `null` rather than fabricated zeroes.

## Where the remaining syscalls are

Ranked, for whenever CPU per Mbit/s becomes worth reducing:

1. `sendmsg`, 35.9% in the baseline -- the equal-size GSO fork targets this cost. Confirm
   its live reduction with `gso_segments_per_batch`, `strace -c`, and CPU seconds/GB.
2. TUN read and write, ~10% plus part of the read cost -- needs `IFF_VNET_HDR` with
   TSO/GRO so the kernel hands over 64 KB segments instead of one packet per syscall.
   `songgao/water` cannot do this; `golang.zx2c4.com/wireguard/tun` can, and its batched
   `Read`/`Write` API is the shape this dataplane already has.

Both target CPU per Mbit/s rather than the Cloudflare per-peer throughput ceiling. The GSO
change is implemented here; TUN offload remains a later, substantially larger change.

## Guardrails

Do not wrap `*net.UDPConn` with a generic `net.PacketConn` just to count writes. quic-go
relies on the concrete UDP connection to enable Linux UDP fast paths such as GSO; changing
the connection type would contaminate the benchmark.

Do not change TUN queueing, checksum behavior, congestion control, or MASQUE framing while
measuring. Compare the new candidate at MTU 1280 against the digest-pinned baseline first;
only then run the separate 1350/1400 MTU experiment.
