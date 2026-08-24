# Egress inspection gateway — POC

Proof of concept for a transparent, TLS-terminating DLP and data-residency
forward proxy on F-Stack. This directory holds the two earliest milestones of
the plan: the CPU-bound bench (M0a) and the single-core vertical slice (POC).

Design target: 70 Gbps of user traffic, 20k connections/s, 1M concurrent
sessions, everything inspected.

## Layout

| Path | Needs | What it does |
|---|---|---|
| `bench/` | OpenSSL only | M0a: measures the CPU-bound lines of the budget |
| `proxy/` | DPDK + libfstack | The vertical slice: intercept, forge, inspect, relay |
| `proxy/host_test.c` | OpenSSL only | Tests the SNI parser and certificate factory |

## M0a — bench the budget

Runs anywhere, no DPDK, no NIC, no root. Run it on the target hardware and the
numbers replace the estimates in the design doc.

```sh
cd bench && make && ./tls_bench          # or: ./tls_bench aead|asym|handshake|copy
```

Exits non-zero if any gate fails. Gates are the values the budget assumes:
AES-GCM >= 4 GB/s/core, ECDSA sign >= 30k/s, ECDH >= 25k/s, handshake pair
<= 150 us, memcpy >= 8 GB/s.

The handshake bench reports the asymmetric primitives separately from the
total, because OpenSSL's per-connection overhead is real cost the gateway pays
on every session and budgets routinely omit it. Run with no arguments to get
that split; the primitives are measured by the `asym` section.

## Host tests — no DPDK required

The ClientHello parser and the certificate factory are verified before
touching the DPDK box, including that a client which trusts the POC CA accepts
a forged leaf with hostname verification on, and rejects a mismatched one.

```sh
cd proxy && make host && ./host_test
```

## POC — the vertical slice

One lcore, explicit `listen` (no transparent interception), origin-first
handshake ordering, a leaf forged per SNI from an in-memory CA, and a relay
that scans plaintext in both directions.

```sh
cd proxy && make                       # needs FF_PATH and PKG_CONFIG_PATH

POC_ORIGIN=<origin-ip>:443 \
POC_LISTEN_PORT=8443 \
POC_PATTERN=SECRET-CANARY \
./poc_proxy --conf config.ini --proc-type=primary
```

Configuration is read from the environment so argv stays free for F-Stack and
DPDK:

| Variable | Default | Meaning |
|---|---|---|
| `POC_ORIGIN` | required | upstream as `ip:port` |
| `POC_LISTEN_PORT` | 8443 | port to listen on |
| `POC_PATTERN` | `SECRET-CANARY` | literal the scan looks for |
| `POC_CA_OUT` | `poc_ca.pem` | where to write the CA to trust |
| `POC_STATS_SEC` | 5 | stats interval, 0 to disable |

Then, from a client that trusts `poc_ca.pem`:

```sh
curl --cacert poc_ca.pem --resolve <origin-host>:8443:<gateway-ip> \
     https://<origin-host>:8443/
```

A request whose body contains the pattern should be dropped, and the counters
should show the match.

### No link on the DPDK port?

The POC does not need a cable. Give F-Stack a TAP device and drive it from the
same host:

```ini
[dpdk]
extra_eal_args=--vdev=net_tap0,iface=ffm0
tx_csum_offoad_skip=1
```

Throughput will be poor; that is fine, since the POC's gate is functional and
its performance numbers come from M0a and later from real hardware.

## POC gate

A real client reaches a real origin through the proxy with content inspected
in between, and single-core handshakes/s and Gbps land within 2x of the M0a
bench figures. A larger gap points at the integration — BIO plumbing, event
loop, or mbuf lifetime — which is what one core is for.

## Known gaps, deliberate

These are scoped out so the POC stays a POC. None are unknowns.

- **Memory BIOs, not mbuf-backed.** Costs about 2.6 cores of copying at target
  scale. The mbuf-backed version needs a write-side segment accessor that the
  lib does not expose yet.
- **No transparent interception.** No `ipfw fwd`, no original-destination
  recovery; the origin is fixed by `POC_ORIGIN`.
- **Single core.** So none of the steering work exists: no symmetric RSS, no
  per-core egress addressing, no flow rules.
- **No send-side queue.** A short write drops the session instead of buffering
  and re-arming for writability.
- **Scan has no streaming state**, so a match spanning two buffers is missed.
  The real engine keeps Vectorscan stream state across buffers.
- **Origin chain is not validated.** Production fails closed on a bad upstream
  chain; the POC accepts anything.
- **No policy, no HTTP parsing, no HTTP/2, no connection pool, no control
  plane, no monitor-only mode.**
