# F-Stack egress inspection gateway — POC findings

What we set out to answer: can a TLS-terminating, content-inspecting forward
proxy on F-Stack beat the same proxy on the Linux kernel stack? The premise of
the whole design is that a userspace stack is faster, so if it cannot at least
match the kernel there is nothing to build on.

The short answer is that the question could not be answered at all until two
genuine F-Stack defects were found and one was fixed, and that once the
measurements became trustworthy the picture is not the one either side of the
argument expected.

Everything below was measured on one core, with the proxy, the load generator
and the origin server all on the same host. Absolute numbers are specific to
that environment; the ratios are the part worth carrying forward.

---

## 1. Headline results

Same core, same NIC, same 1 MB object, both stacks running identical
application code (only the platform layer differs).

| concurrency | proxy on F-Stack | proxy on kernel |
|---|---|---|
| 1 | 18–24 MB/s | 37 MB/s |
| 8 | 39–47 MB/s | 375–419 MB/s |
| 32 | 322–352 MB/s | 412–470 MB/s |

And the calibration that puts those in context — each stack's *own* reference
server, one core, `sendfile off` on both so it is the stack being compared:

| workload | F-Stack nginx | Linux nginx |
|---|---|---|
| 1 MB, c=1 | 2.50 MB/s | 1.37 GB/s |
| 1 MB, c=8 | 29.3 MB/s | 2.29 GB/s |
| 1 MB, c=32 | 110.8 MB/s | 2.33 GB/s |
| small object, c=8 | 23,523 rps | 33,233 rps |
| small object, c=32 | 61,069 rps | 59,318 rps |

Three things follow.

**F-Stack's performance claim holds where F-Stack makes it.** On small objects
it is at par with Linux and slightly ahead at higher concurrency. Every
benchmark F-Stack publishes is of this shape: its README charts are CPS,
CPS_Reuseport and RPS at "small data packet", and Bandwidth at 3.7 KB. There
is no published proxy number and nothing above 3.7 KB.

**On bulk transfer F-Stack is roughly 21× behind Linux**, measured with its own
flagship application. This is not our proxy, our relay design, or our tuning.

**Our proxy is about 3× faster than F-Stack's own nginx** on the same bulk
workload, while doing far more work: two TCP legs, TLS termination on both,
certificate forging and content scanning. Whatever ails F-Stack's bulk path,
this code works around it better than F-Stack's own application does.

That also reframes the proxy comparison. Linux nginx reaching 2.33 GB/s shows
the kernel stack is nowhere near its limit at 412–470 MB/s, so the kernel proxy
is **crypto and scan bound**. The F-Stack proxy at 322–352 is still fighting
the stack. The remaining gap is not "the kernel is faster at proxying"; it is
"the kernel proxy already hit the CPU wall and the F-Stack one has not."

---

## 2. F-Stack defects found

### 2.1 TCP timers never fired at all — fixed

`callout_when()` in `lib/ff_stub_14_extra.c` was an empty function body. It is
the function `tcp_timer_activate()` calls to compute a timer's deadline:

```c
callout_when(tick_sbt * delta, 0, C_HARDCLOCK,
             &tp->t_timers[which], &tp->t_precisions[which]);
```

With nothing written to `t_timers[which]` it kept its initialised `SBT_MAX`,
`tcp_timer_next()` reported no timer pending, and the arming path fell through
to `callout_stop()`. **Every request to start a retransmit, persist,
delayed-ACK or keepalive timer stopped it instead.** `tcp_timer_enter` fired
zero times in the entire lifetime of a process.

A second defect sat underneath. `callout_reset_sbt_on` is a macro that divides
its `sbintime` by `tick_sbt` to index a tick-based callwheel — correct for a
duration, wrong for the absolute deadline `tcp_timer_activate` passes with
`C_ABSOLUTE`, which schedules the callout roughly uptime-in-ticks away.

**Symptom.** A connection died on its first lost segment. Nothing retransmitted
it, `snd_una` never advanced, the congestion window stayed full of unacked
data, `tcp_output` computed `len=0` forever, and the send buffer could never
drain, so writes returned `EAGAIN` for as long as the process lived. A 1 MB
transfer stopped at a repeatable byte count and hung:

| sendspace | bytes delivered before the stall |
|---|---|
| 16 KB | 732,724 |
| 64 KB | 418,452 |
| 512 KB | 364,788 |

Identical on every connection and every run. Smaller buffers got *further*,
because less data in flight means the first loss comes later.

**Why nobody had hit it.** Small responses never put enough in flight to lose
any. F-Stack's own benchmarks are all small-object, so its entire published
performance story runs on a path where this bug is invisible.

**Diagnosis chain**, for the record, because most of it was wrong before it was
right: the wire capture showed the sender stopping dead with the peer window
open and everything ACKed; `tcp_output`'s decline path showed
`len=0 off=17376 cwnd=17376` — congestion window exactly equal to bytes in
flight; then `rexmt_armed=0` with `snd_nxt != snd_una`; then
`tcp_timer_enter` never firing.

Fix: implement `callout_when()`, and convert absolute deadlines to a tick delay
by subtracting current uptime. With timers running, that transfer completes and
a single connection moves about 297 MB/s.

Reproducer: `poc/bench/fstack_bulk.c` — ~200 lines, no TLS, no relay, no
certificates. Accept, write a large body, handle short writes. Suitable as-is
for an upstream bug report.

### 2.2 LRO could not be enabled on any PMD reporting no LRO size — fixed

Setting `lro=1` killed the port at startup:

```
LRO is supported
ETHDEV: Ethdev port_id=0 max_lro_pkt_size 16384 != 8884 is not allowed
EAL: Error - exiting with code: 1
```

When a PMD reports `max_lro_pkt_size = 0` — vmxnet3 does —
`rte_eth_dev_configure` requires the configured value to equal the frame length
it derives from the MTU. `ff_dpdk_if.c` passed `dev_info.max_rx_pktlen`
instead. It was also sized in the wrong place: the LRO block runs before
`port_conf.rxmode.mtu` is assigned, so the MTU it needs is not yet known.

Fix: size it immediately before `rte_eth_dev_configure`, deriving the overhead
the way ethdev does. LRO is then usable and worth **+16–21%** — receive queue
depth roughly doubled (31,497 → 68,087 bytes) and average read size grew
(11,879 → 13,875 bytes).

### 2.3 Data arrives and the application is never woken — NOT fixed

This is the root cause of the bulk deficit, and of the 548x gap at one
connection between F-Stack nginx (2.50 MB/s) and Linux nginx (1.37 GB/s).

A keep-alive sequence of three 1 MB requests, captured on the wire:

```
client requests sent:  t=308.521704, 308.525983, 308.531665   (all within 10ms)
retransmissions:       none -- each sequence number appears exactly once
largest gap:           231.6 ms, before a packet FROM THE SERVER
per-request times:     4.5 ms, 5.6 ms, 281 ms
```

The client sent all three requests promptly and never retransmitted, so the
third was received. The server then sat on it for 231.6 ms. F-Stack's
retransmit timeout on these connections is `rxtcur=230` ticks, so the response
was not triggered by the arriving request at all -- it was triggered 230 ms
later by the stack's own retransmit timer happening to run the input path.

Three independent measurements agree:

- **Wakeups arrive at about 1000 per second per connection**, which is exactly
  `hz=1000`. The application is being scheduled by the clock, not by data.
- **A new connection is fast, a reused one is slow.** Twelve fresh connections
  fetched 1 MB in 2.9-4.4 ms each, about 340 MB/s. The same fetch on an
  already-open connection takes hundreds of milliseconds.
- **Level-triggered readiness works around it; edge-triggered does not.** Our
  proxy re-evaluates the filter on every kevent scan and is ~10x faster than
  F-Stack's own nginx on the same stack. nginx registers with `EV_CLEAR` and
  depends on the activation that never comes.

`kqueue_register` itself is correct -- it re-evaluates the filter after `EV_ADD`
at `done_ev_add` -- so the fault is upstream of kqueue, in whatever should
activate the knote when the socket receives data.

**Why F-Stack's published numbers do not show this.** Its benchmarks are all
small objects, where a request and its response need one or two wakeups. The
cost of a missed wakeup is bounded by a timer tick, so the damage is small and
constant. A 1 MB transfer needs hundreds of wakeups, and each one that is
missed costs up to a retransmit timeout. The defect is invisible at 3.7 KB and
ruinous at 1 MB.

This also retracts an earlier conclusion recorded in section 4: the
"asynchrony" explanation -- that a run-to-completion loop drains too eagerly to
accumulate a batch -- described a real effect but was not the main cause. The
main cause is missed wakeups. Section 4's measurements stand; its
interpretation is superseded by this one.

### 2.4 The port stops receiving, permanently — NOT fixed

Seen twice, once under the reference server and once under the proxy.
`rte_eth_rx_burst` returns nothing for as long as the process lives:

```
ipkts frozen   opkts frozen   ierr=0  oerr=0
mbuf=15361/16384 (pool healthy)   link=up/10000Mbps
```

ARP to the port fails, so peers give up. Only a process restart revives it.
Both occurrences followed heavy `imissed` — 50,251 in one case. This is the
most dangerous open item: in production it is an unrecoverable hang. Link state
and port counters are now reported every stats interval to catch the next one.

---

## 3. Proxy defects found

All of these were latent behind a POC gate that only ever moved small objects.

| defect | symptom | why it hid |
|---|---|---|
| short writes dropped the session and lost data | 1 MB object returned 130,817 bytes | nothing under ~128 KB reached the path |
| one read per event under edge-triggered readiness | 40 KB/s crawl | small objects finish in one read |
| `ENOBUFS` treated as fatal | sessions died mid-transfer under load | Linux never returns it there; F-Stack only |
| `ev_watch` meant different things per backend | arming write interest would silently drop read interest on epoll | never exercised until backpressure existed |
| forged leaf copied the origin's validity window | every verifying client failed; load generators sailed through | `wrk` does not verify certificates |

That last one deserves emphasis as a methodology trap. The rig's origin
certificate was issued for one day. Once it expired, the gateway was minting
certificates that had expired before they were signed. `curl --cacert` failed
every handshake while `wrk` kept reporting throughput, so an entire class of
measurement looked merely erratic while a verifying client could not connect at
all. The leaf now gets its own window, and there is a regression test that
mints from an expired origin and requires the result to be valid now.

### Self-inflicted overhead, found by cycle counting

`perf` is the wrong instrument for a busy-polling process — sampling dragged
throughput from tens of MB/s to 1.3 and produced a profile describing a loop
spinning with no work rather than the work itself. We were misled by it once.
Direct rdtsc counters around calls that already do real work, placed in code
both backends share, found:

- `SSL_read` called **4,037,245 times to move data 4,058 times** — one read in
  a thousand did anything, costing ~40% of the core. Cause: a congested session
  was re-queued and re-read its source every pass, and a leg congested towards
  its peer usually has a source with nothing to give.
- then 9.4M socket writes for 6,623 chunks (~25% of the core) — the same
  workaround on the write side. It only existed to paper over §2.1; with timers
  working, waiting for write readiness is correct again.
- `pkt_tx_delay=0` made F-Stack flush every packet individually. Restoring
  batching cut poll overhead **260×** (30.8% / 8.5M calls → 0.2% / 32,860).

After all three, the proxy's own work is ~17% of the core at c=32.

---

## 4. Why the gap remains, and why c=8 is the worst case

The measurement that explains it — bytes moved per relay visit, both builds
issuing the same 16 KB reads:

| concurrency | kernel | F-Stack |
|---|---|---|
| 1 | 110.6 KB | 5.5 KB |
| 8 | 167.8 KB | 6–8 KB |
| 32 | 170.8 KB | 12–17 KB |

The kernel gets a fat batch at every concurrency, including a single
connection. **Its receive path runs concurrently with the application**: while
the proxy spends milliseconds on crypto, softirq keeps filling the socket, so
the next read finds ~168 KB waiting. One visit, one big batch, about six visits
per 1 MB response.

A run-to-completion stack shares one thread between stack and application, so
the relay drains each connection the instant data lands and never accumulates
anything. Every ~7 KB costs a full loop iteration plus an `SSL_read` plus a
socket read — about 146 visits per 1 MB instead of six.

At c=8 this is at its worst because the loop is only ~17% busy: it cycles fast
enough to drain every connection promptly. At c=32 it finally has enough work
to fall behind, ~26 KB accumulates between visits, and efficiency recovers.
**F-Stack only batches by accident, when it is too busy to be prompt** — which
is why aggregate throughput scales superlinearly (24 → 42 → 342 MB/s) and why
per-connection throughput dips at 8 and recovers at 32.

Deliberate batching does not fix it, and the failure is informative. Waiting
for a worthwhile batch before spending a visit:

| `POC_RX_BATCH` | c=1 | c=8 | c=32 |
|---|---|---|---|
| off | 18.4 | 40.9 | 322.7 |
| 32 KB | 1.7 | 10.3 | 347.9 |
| 128 KB | 0.5 | 7.6 | 351.6 |

It buys a little at high concurrency and destroys the low end, because the low
end is **latency-bound, not efficiency-bound**: the origin sits idle waiting for
the next request, so any delay added to a read is added to the whole cycle. The
knob remains, defaulted off.

---

## 5. What was ruled out

Recorded because each cost real time and none of them is the answer.

| hypothesis | evidence against |
|---|---|
| hypervisor offloads (TSO/GSO/GRO/**LRO**) | disabling all four costs the kernel only ~6% (375 → 354 MB/s) |
| per-packet cost | follows from the above — the kernel proxy is per-byte bound |
| packet loss | drops scale *with* throughput: 54,780 drops at 335 MB/s, 8,003 at 163 MB/s |
| mbuf leak / pool exhaustion | free count steady at 14–15k of 16,384; `rxnombuf=0` |
| clock or timer pathology | clocksource `tsc`; stack clock within 1 ms of host, idle and loaded |
| receive window | proxy advertises 262–384 KB on the wire |
| `ff_read` withholding data | `FIONREAD` before each read showed only ~9 KB genuinely queued |
| delayed ACK | `net.inet.tcp.delayed_ack: 0` verified applied in the running stack |
| F-Stack itself being slow | its stock example server sustains ~150k rps (~300k pps) on one core |
| CPU saturation | freeing 30% of the core via `pkt_tx_delay` changed throughput not at all |

---

## 6. Methodology traps

Worth reading before trusting any number from this rig.

- **Busy-poll defeats CPU-based metrics.** An F-Stack worker reads 100% at any
  load, so "cores at fixed load" is meaningless and 100% CPU is not evidence of
  saturation. Compare saturation throughput at equal core count instead.
- **The generator is a bottleneck.** `wrk` alone consumed 273% CPU — 91% of the
  three non-isolated cores — pinning both stacks at ~750–790 CPS regardless of
  anything else. Always sample generator CPU alongside the result.
- **Load generators do not verify certificates.** See §3. A TLS fault that
  blocks every real client can be invisible to a load test.
- **Sensor services restart themselves.** `systemctl disable` was not enough;
  services returned and one pinned a generator core at 100% mid-measurement.
  `systemctl mask` held. Any result from that window is void.
- **`perf` distorts busy-poll processes** by more than an order of magnitude.
- **`pkill -f <pattern>` matches your own shell** when the pattern appears in
  its argv. This killed measurement scripts repeatedly.
- **F-Stack's `netstat` tool is unreliable here** — it reported a fixed
  TIME_WAIT count regardless of load or elapsed time, and failed with ENOMEM on
  `-s`. Its zeros are not data.

---

## 7. Budget checks

From `poc/bench/tls_bench.c` and `poc/bench/scan_bench.c`, single core:

| line | measured | gate | verdict |
|---|---|---|---|
| AES-256-GCM | 12.4 GB/s | ≥ 4.0 | pass |
| ECDSA P-256 sign | 54.8k/s | ≥ 30k | pass |
| ECDH P-256 | 15.4k/s | ≥ 25k | **fail** |
| TLS 1.3 handshake pair | 541.7 µs | ≤ 150 | **fail** |
| inspection, 100 bounded patterns | 2.33 GB/s | ≥ 2.0 | pass |

The handshake figure is 207 µs of primitives plus 334 µs of OpenSSL
per-connection overhead, and is the line most likely to force a design change
at 20k CPS.

Inspection at 2.33 GB/s implies **3.75 cores for 70 Gbps** against the 4.4
budgeted, on a host without AVX2 — so that line holds with margin. Streaming
mode measured both faster and cheap in memory (37 bytes per stream, ~0.07 GB at
1M sessions × 2 directions), which inverts the earlier assumption that block
mode with an overlap window would be the cheaper choice.

---

## 8. Open questions

1. **Missed wakeups on data arrival (§2.3).** The root cause of the bulk
   deficit. Find what should activate the socket's knote on receive and does
   not. Highest priority, and the most likely single fix to close the gap.
2. **The port RX death (§2.4).** Unrecoverable in production.
3. **Is any of the residual deficit vmxnet3-in-a-VM?** The environment charges
   a doorbell-per-transmit VM exit, offers no working hardware offloads and
   runs under `uio_pci_generic` without MSI-X. F-Stack's own nginx being 21×
   behind Linux points at the environment as much as the stack. A real NIC
   settles it, and the target is a 100G NIC anyway.
4. **Scaling across cores** — F-Stack's actual design point and the source of
   all its published numbers. Entirely untested here; a 25% per-core deficit
   matters much less if scale-out is linear.
5. **Jumbo frames.** 6× fewer packets, larger reads per arrival, helps exactly
   the metric we are short on. Cheap, untested.
6. **Pipeline split** — dedicated RX cores feeding workers over rings, which
   attacks the asynchrony in §4 rather than working around it. Real work, and
   not native to F-Stack's shared-nothing model.

## 9. Reproducing

```
poc/bench/tls_bench.c     crypto and handshake budget, no DPDK
poc/bench/scan_bench.c    inspection throughput, takes -f patterns.txt
poc/bench/fstack_bulk.c   minimal F-Stack bulk sender (the §2.1 reproducer)
poc/proxy/                the proxy itself, STACK=fstack | STACK=kernel
```

Runtime knobs that matter: `POC_RELAY_BUDGET` (bytes one leg moves per visit),
`POC_LOOP_BUDGET` (bytes the whole loop moves per pass), `POC_RX_BATCH` and
`POC_RX_WAIT_US` (receive batching, off by default). In `config.ini`:
`lro`, `pkt_tx_delay`, `net.inet.tcp.sendspace` / `recvspace`.

The proxy prints per-interval cycle accounting by phase, event yield, bytes per
relay visit, read sizes against queue depth, DPDK port counters, link state and
stalled-session state. Those counters are how every conclusion above was
reached, and they are worth keeping.
