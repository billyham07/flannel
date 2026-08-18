# Cloudflare Mesh syscall profiling

This note captures the current performance evidence for the native MASQUE transport and the next measurement step before changing the dataplane.

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

## Working hypothesis

The current ceiling is per-packet syscall and QUIC DATAGRAM overhead rather than allocation, checksum work, or the flannel routing path.

The next experiment should answer two questions without changing transport semantics:

1. Is UDP GSO actually batching multiple QUIC packets per kernel send, or are we effectively paying one `sendmsg` per datagram?
2. Are QUIC DATAGRAM send/receive queues introducing backpressure or drops that correlate with inner TCP retransmits?

## Measurement requirements

For the same 60 second iperf3 workload, capture:

- QUIC packets emitted
- UDP send syscalls
- average GSO segments per send
- datagram send-queue block count and blocked time
- datagram receive-queue drops
- receive-queue high-water mark
- inner TCP retransmits
- flanneld CPU and pprof CPU profile

The important derived values are:

```text
avg_packets_per_send = quic_packets / udp_send_syscalls
retransmit_delta ~= datagram_receive_queue_drops ?
```

## Guardrails

Do not wrap `*net.UDPConn` with a generic `net.PacketConn` just to count writes. quic-go relies on the concrete UDP connection to enable Linux UDP fast paths such as GSO; changing the connection type would contaminate the benchmark.

Do not change TUN queueing, checksum behavior, MTU, congestion control, or MASQUE framing in the same experiment. This PR is intentionally measurement-only so the next dataplane change can be selected from evidence.
