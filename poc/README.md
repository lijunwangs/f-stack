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
| `proxy/` (`STACK=kernel`) | OpenSSL only | The same proxy on kernel sockets, as a control |
| `proxy/host_test.c` | OpenSSL only | Tests the SNI parser and certificate factory |

### Two builds of the same proxy

```sh
make                  # F-Stack + DPDK
make STACK=kernel     # kernel sockets + epoll, no DPDK
make both             # both, for a like-for-like comparison
```

All the proxy logic lives in `main.c`, `session.c`, `sni.c`, `forge.c` and
`scan.c` and is shared verbatim. `net.h` is a small platform layer with two
implementations -- `net_fstack.c` (`ff_*` plus kqueue) and `net_kernel.c`
(POSIX plus epoll) -- so `ff_*` appears in exactly one file. Sockets map one
to one; only the event loop needed real translation, and since the proxy only
ever asks to watch an fd for read or write, a three-call abstraction
(`ev_create`, `ev_watch`, `ev_wait`) covers both without emulating either.

Verify both behave identically before trusting the layer. The kernel build
runs over loopback with no veth, no DPDK and no root:

```sh
POC_ORIGIN=127.0.0.1:9443 POC_LISTEN_PORT=8443 \
    POC_CA_OUT=poc_ca_kernel.pem \
    ./poc_proxy_kernel > poc_kernel.log 2>&1 &
STACK=kernel ./test_single_box.sh
```

Each build writes its own CA, because the two mint different keys -- verifying
against the wrong one fails in a way that looks like a proxy bug. If an earlier
`sudo` run left root-owned `poc_ca.pem` or `origin_*.pem` behind, remove them
first: the unprivileged build cannot overwrite them.

If both builds pass the same three checks, the abstraction is sound and any
later performance difference between them is attributable to the transport.

The kernel build earned its keep immediately by exposing a real bug: entering
the relay state without draining what was already buffered. On loopback a
client's Finished and its first request arrive in the same segment, so one read
pulls both into the BIO -- and with edge-triggered readiness on either stack, no
further event ever comes and the session hangs. F-Stack had been getting lucky
on segment timing.

This exists to make a comparison against a stock proxy interpretable. Measuring
the POC against Envoy directly conflates three variables: userspace TCP versus
kernel, OpenSSL versus BoringSSL, and our state machine versus a mature filter
chain. The kernel build isolates the first:

| Comparison | Isolates |
|---|---|
| F-Stack build vs kernel build | the kernel-bypass delta, everything else identical |
| kernel build vs Envoy | our implementation versus a mature one |

Metric to report: **cores consumed at a fixed offered load**, not peak
throughput -- "who tuned harder" is an unwinnable argument, while cores per
1000 CPS is what a capacity plan uses. `bench_proxy.sh` measures exactly that
against any proxy:

Benchmarking needs a *persistent* origin — `test_single_box.sh` starts one and
kills it on exit, so a passing functional test does not mean one is running.
`origin.sh` provides one, preferring nginx because `openssl s_server` is single
threaded and caps the measured rate well below what the proxy can do.

```sh
sudo apt install -y wrk nginx nghttp2-client   # generators and a real origin
./origin.sh start                              # 127.0.0.1:9443

# connection rate: a new TLS handshake per request
./bench_proxy.sh -t origin.test.invalid:8443 -a 127.0.0.1 \
                 -c poc_ca_kernel.pem -p poc_proxy_kernel \
                 -m cps -l poc_kernel.log

# throughput: keepalive, exercising the relay and scan path
./bench_proxy.sh -t origin.test.invalid:8443 -a 127.0.0.1 \
                 -c poc_ca_kernel.pem -p poc_proxy_kernel -m rps

# same harness against anything else, Envoy included
./bench_proxy.sh -t origin.test.invalid:10000 -a 127.0.0.1 -p envoy -m cps
```

`-m cps` is the one that matters most, since the measured budget puts the cost
in handshakes. It requires **wrk**: h2load does not reconnect after the server
closes, so with `Connection: close` it issues one request per client and then
sits idle reporting a rate of zero. `-m rps` uses keepalive and measures the
relay instead, where h2load is fine.

**Pass `-l <proxy log>` in cps mode.** wrk's own accounting is unusable there:
it treats every close-delimited response as a read error and reports zero
requests even while moving tens of megabytes. With `-l` the harness reads the
rate from the proxy's own `sessions=` counter, which cannot be confused this
way. Latency in cps mode is meaningless for the same reason — use `-m rps` when
you want percentiles.

Either way the harness reads the proxy's own `utime + stime` from
`/proc/<pid>/stat` and reports cores consumed and cores per 1000 CPS.

Two cautions. Any comparison is meaningless unless both proxies do equivalent
work -- TLS termination, an upstream TLS connection, and the same inspection;
Envoy in passthrough proves nothing. And do not draw platform conclusions from
the veth rig: `af_packet` over veth is one of the slowest DPDK paths there is,
so it handicaps F-Stack in a way the real NIC will not. Comparative runs belong
on the deployment hardware.

## Building

Three layers: DPDK, then `libfstack`, then the POC. Only the last one is ours.

```sh
# 1. dependencies (Ubuntu)
sudo apt update
sudo apt install -y git gcc make meson ninja-build python3-pyelftools \
                    libssl-dev libnuma-dev pkg-config

# 2. DPDK
cd $FF_PATH/dpdk
meson setup -Denable_kmods=false build
ninja -C build
sudo ninja -C build install
sudo ldconfig

# 3. point pkg-config at it, and confirm
export PKG_CONFIG_PATH=/usr/local/lib/x86_64-linux-gnu/pkgconfig:/usr/local/lib64/pkgconfig:$PKG_CONFIG_PATH
pkg-config --modversion libdpdk        # expect 24.11.x

# 4. the F-Stack library (slow: it builds the FreeBSD sources)
export FF_PATH=~/f-stack               # wherever the repo lives
cd $FF_PATH/lib
make -j$(nproc)
# `make install` is optional: the POC takes headers and libfstack.a straight
# from the tree. The in-tree examples do need it.

# 5. the POC
cd $FF_PATH/poc/proxy
make
```

**`-Denable_kmods=false` is deliberate.** The repo's build guide uses `true`,
which builds the `igb_uio` and `kni` kernel modules. They are not needed here:
the single-box setup runs with `--no-pci` and a TAP device, so no interface is
ever bound to a userspace driver. On a recent kernel those modules are also
liable to fail to build, taking the whole DPDK build down with them.

If step 3 cannot find `libdpdk`, locate the file and set the path to its
directory:

```sh
find / -name libdpdk.pc 2>/dev/null
```

### "Cannot get hugepage information" at startup

DPDK needs hugepages even with `--no-pci` and a TAP device. Reserve 2 MB pages
at runtime -- 1024 per node is 2 GB each:

```sh
echo 1024 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 1024 | sudo tee /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
grep Huge /proc/meminfo
mount | grep hugetlbfs || sudo mount -t hugetlbfs nodev /dev/hugepages
```

Only the node owning the worker lcore is strictly required. Uncommenting
`no_huge=1` in `config.ini` also works, but it disables multi-process sharing,
which the per-core worker model needs later -- prefer reserving the pages.

### Link errors for libjitterentropy or libzstd

`libdpdk.pc` carries OpenSSL's *static* private dependencies transitively,
which is where `-l:libjitterentropy.a` and `-lzstd` come from -- OpenSSL 3.5
added a jitterentropy seed source and zstd compression. Since this POC links
OpenSSL dynamically, `libcrypto.so` resolves those internally and they are
spurious. The Makefile already filters out `-l:libjitterentropy.a`, which
Ubuntu does not package at all. For zstd:

```sh
sudo apt install -y libzstd-dev
```

To drop a different one instead, override the filter:

```sh
make DPDK_DROP_LIBS="-l:libjitterentropy.a -lzstd"
```

`DPDK_SHARED=1` looks like an easier way out and is not: F-Stack adds
`rte_timer_meta_init` to `dpdk/lib/timer/` but never lists it in that
library's `version.map`, so the symbol is present in the static archive and
absent from `librte_timer.so`. Linking dynamically against the fork as shipped
therefore fails on that symbol no matter what else is installed. Making it
work means adding the symbol to the version map and rebuilding DPDK.

The bench and the host tests need none of this — only `libssl-dev`.

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

### No cable, no public address, one box

The POC needs neither a link nor outbound connectivity. `config.ini.sample`
runs F-Stack on one end of a veth pair with `--no-pci`, so DPDK never probes a
physical interface and the management NIC cannot be taken over -- and no IOMMU,
vfio or NIC binding is involved. `poc_ctl.sh start` creates the pair: the
kernel keeps `ffhost` at `10.99.0.1`, DPDK takes `ffdpdk`, and F-Stack's own
stack answers on `10.99.0.2`.

Two subtleties, both learned the hard way:

**F-Stack runs its own IP stack**, so `ff_connect` cannot reach a service on the
kernel's `127.0.0.1`. The origin has to sit on the kernel side of the link with
its own address.

**Turn the veth offloads off.** On a local pair the kernel leaves TCP
checksums as `CHECKSUM_PARTIAL`, so the checksum field holds a pseudo-header
sum rather than a real checksum -- normally the peer stack on the same host
just trusts it. `af_packet` hands the frame to F-Stack unchanged, F-Stack
validates in software, and the segment is dropped. Because ICMP is always
checksummed in software, the symptom is that ping works perfectly while TCP
never connects and every session count stays at zero. `poc_ctl.sh` runs
`ethtool -K ... tx off rx off gso off tso off gro off` on both ends for this
reason.

**Do not use the TAP PMD for this.** With `net_tap` the DPDK port and the
kernel netdev are the same device, so both stacks share one MAC address. The
kernel's ARP request for `10.99.0.2` then arrives carrying F-Stack's own
sender MAC, and FreeBSD's ARP input drops it at
`freebsd/netinet/if_ether.c:899` as self-originated. There is no log line and
no counter: pings simply go unanswered and every session count stays at zero.
A veth pair gives the two stacks separate netdevs, hence separate MACs, and
ARP resolves normally.

The TAP device only exists once DPDK has initialised it, so the gateway
starts first and the kernel side is configured afterwards.

```sh
cp config.ini.sample config.ini        # then set lcore_mask

sudo ./poc_ctl.sh start                # background; creates ffm0
sudo ./test_single_box.sh              # configures the TAP, origin, checks
sudo ./poc_ctl.sh status               # pid, TAP state, last stats line
sudo ./poc_ctl.sh log                  # follow poc_proxy.log
sudo ./poc_ctl.sh stop
```

`poc_ctl.sh start` clears `/var/run/dpdk/rte` first, because an unclean exit
leaves DPDK runtime state that makes the next EAL init fail on a stale socket.
To run it in the foreground instead, which is easier when something is wrong:

```sh
sudo POC_ORIGIN=10.99.0.1:9443 ./poc_proxy --conf config.ini --proc-type=primary
```

`test_single_box.sh` verifies three things: that a request completes through
the gateway; that the certificate the client is served is issued by the POC CA
rather than the origin, which is what distinguishes interception from
passthrough; and that a body carrying the canary is blocked, which proves
plaintext actually reaches the scanner.

To drive it by hand, use `--resolve` rather than an IP URL -- the POC keys
everything on SNI, and clients do not send SNI for IP literals:

```sh
curl -v --cacert poc_ca.pem \
     --resolve origin.test.invalid:8443:10.99.0.2 \
     https://origin.test.invalid:8443/
```

Throughput over TAP is poor, which is fine -- the POC's gate is functional, and
its performance figures come from M0a and later from real hardware.

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
  and re-arming for writability. Fine for small objects over a veth link;
  the real implementation needs a per-direction output queue.
- **Scan has no streaming state**, so a match spanning two buffers is missed.
  The real engine keeps Vectorscan stream state across buffers.
- **Origin chain is not validated.** Production fails closed on a bad upstream
  chain; the POC accepts anything.
- **No ALPN.** The forged context negotiates nothing, so clients log "server
  does not support ALPN" and fall back to HTTP/1.1. Harmless here; the real
  implementation must mirror the origin's ALPN, and must offer h2 (§08 of the
  design doc — gRPC cannot fall back).
- **No policy, no HTTP parsing, no HTTP/2, no connection pool, no control
  plane, no monitor-only mode.**
