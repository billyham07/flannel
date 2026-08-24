# Flannel with Native Cloudflare Mesh Backend 🌐

[![Go Report Card](https://goreportcard.com/badge/github.com/billyham07/flannel)](https://goreportcard.com/report/github.com/billyham07/flannel)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Backend](https://img.shields.io/badge/Backend-Cloudflare%20Mesh%20(MASQUE)-F38020?logo=cloudflare&logoColor=white)](https://www.cloudflare.com/products/zero-trust/)

A specialized, high-performance distribution of **Flannel** featuring a **native, pure-Go Cloudflare Zero Trust Mesh backend**.

Designed for hybrid-cloud, edge-to-cloud, and multi-region Kubernetes clusters, it establishes high-throughput pod-to-pod overlays traversing Cloudflare's global Anycast edge via **MASQUE (RFC 9484: CONNECT-IP over HTTP/3 / QUIC)** — with **zero external daemons (no `warp-cli` required)**.

---

## 🚀 Key Highlights & Innovations

* **Pure-Go Native MASQUE Dataplane**: Complete userspace implementation of CONNECT-IP over HTTP/3. Pod traffic flows directly through Linux TUN into embedded QUIC sessions without running heavy external WARP/WireGuard daemons.
* **Kubernetes Native Operator**: Automated node lifecycle, device provisioning, key rotation, and automated GC reclamation of orphaned Cloudflare Zero Trust device seats.
* **Production-Grade Syscall & Memory Optimizations**:
  * **Bounded TUN Buffer Recycling**: Zero-allocation hot path with reusable slice buffers, reducing GC cycles by ~36%.
  * **Dynamic MTU & QUIC Packet Sizing**: Eliminates the MTU mismatch black-hole defect by dynamically deriving initial QUIC packet buffers from the configured TUN MTU.
  * **Equal-Size UDP GSO Batching**: Custom `quic-go` patch supporting `UDP_SEGMENT` GSO batching for CONNECT-IP datagrams, slashing send-side syscall overhead.
  * **HTTP/3 Burst Absorption**: Extended buffering queues prevent silent datagram drops during packet bursts.
* **Deep Diagnostics & Telemetry**: Built-in `/debug/cloudflare-mesh/stats` endpoint exposing real-time RTT, QUIC loss, HTTP/3 datagram queue watermarks, and GSO efficiency counters.

---

## 🏗️ Architecture

```
+-------------------------------------------------------------------------------+
|                             Kubernetes Node                                   |
|                                                                               |
|  +-------------+       +-------------------+       +-----------------------+  |
|  | Pod Network | ----> |   flannel.mesh    | ----> |  pkg/backend/         |  |
|  | (10.244/16) |       |  (TUN Device)     |       |  cloudflaremesh       |  |
|  +-------------+       +-------------------+       +-----------+-----------+  |
|                                                                |              |
|                                                     [CONNECT-IP / HTTP3 / QUIC]
|                                                                |              |
+----------------------------------------------------------------|--------------+
                                                                 | UDP / 443
                                                                 v
                                            +-----------------------------------+
                                            |   Cloudflare Global Anycast Edge  |
                                            |       (Zero Trust Mesh IP)        |
                                            +-----------------------------------+
```

---

## 📊 Performance & Syscall Benchmarks

Tested on a 5-node distributed Kubernetes cluster across **Hong Kong, Japan, and Sydney** (see detailed profiling notes in [`Documentation/cloudflare-mesh-syscall-profiling.md`](Documentation/cloudflare-mesh-syscall-profiling.md)):

* **Multi-Node Fan-out Throughput**: **434 Mbit/s** across 3 concurrent multi-region peer nodes through a **single flanneld instance** and single MASQUE session.
* **GC Pressure Reduction**: Dropped GC invocation frequency from **20.9/s to 13.3/s** under sustained line-rate traffic.
* **Zero Packet Drop**: Eliminated silent drops on full-MTU packet ingress during QUIC path discovery.

---

## ⚙️ Configuration

Set the backend to `cloudflare-mesh` in your Flannel `net-conf.json`:

```json
{
  "Network": "10.244.0.0/16",
  "Backend": {
    "Type": "cloudflare-mesh",
    "InterfaceName": "flannel.mesh",
    "MeshCIDR": "100.96.0.0/12",
    "MTU": 1280,
    "RouteTable": 51820,
    "ConnectTimeout": "45s",
    "KeepalivePeriod": "30s",
    "ReconcilePeriod": "30s"
  }
}
```

### Configuration Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `Type` | string | - | Must be set to `cloudflare-mesh` |
| `InterfaceName` | string | `flannel.mesh` | Name of the local TUN device created on the host |
| `MeshCIDR` | string | `100.96.0.0/12` | Cloudflare Zero Trust Mesh IP allocation pool |
| `MTU` | int | `1280` | MTU for the overlay network interface |
| `RouteTable` | int | `51820` | Policy routing table ID for pod mesh traffic |
| `KeepalivePeriod` | string | `30s` | Periodic session ping interval for MASQUE sessions |

---

## 📦 Deployment via Helm

```bash
# 1. Install the Cloudflare Mesh CRD and Operator
helm install cloudflare-mesh-operator ./chart/kube-flannel \
  --namespace kube-flannel \
  --create-namespace \
  --set cloudflareMesh.enabled=true \
  --set cloudflareMesh.apiToken="<CLOUDFLARE_API_TOKEN>" \
  --set cloudflareMesh.accountID="<CLOUDFLARE_ACCOUNT_ID>"

# 2. Verify mesh connectivity and node registration
kubectl -n kube-flannel get nodes -o wide
```

---

## 🔍 Observability & Live Stats

When loopback diagnostics are enabled, querying `http://127.0.0.1:6060/debug/cloudflare-mesh/stats` outputs live transport health metrics:

```json
{
  "quic_rtt_ms": 14.2,
  "quic_loss_count": 0,
  "http3_datagram_drops": 0,
  "tun_buffer_pool_exhaustion": 0,
  "gso_segments_per_batch": 3.44,
  "active_masque_sessions": 1
}
```

---

## 🔗 Related Upstream & Fork Ecosystem

This project relies on optimized low-level transport forks:
* **[`billyham07/quic-go`](https://github.com/billyham07/quic-go)**: Patched with equal-size GSO segment coalescing and transport drops observability.
* **[`billyham07/connect-ip-go`](https://github.com/billyham07/connect-ip-go)**: Tailored for Cloudflare Zero Trust MASQUE framing compatibility.

---

## Standard Flannel Features

All standard Flannel backend options (VXLAN, host-gw, WireGuard, etc.) remain supported. For upstream documentation, see the [official Flannel docs](https://github.com/flannel-io/flannel).
