#!/bin/sh
# Measure a running proxy under fixed load and report cores consumed.
#
# The metric is CPU per unit of work, not peak throughput: "who tuned harder"
# is an unwinnable argument, while cores per 1000 CPS is what a capacity plan
# actually uses. Works against either build, and against Envoy or any other
# proxy -- point it at a host:port and give it the process to account for.
#
#   ./bench_proxy.sh -t <host>:<port> -a <addr> -c <cacert> -p <pid|name> \
#                    [-m cps|rps] [-d seconds] [-C connections] [-l logfile]
#
# Pass -l to read the rate from the proxy's own session counters instead of
# the generator's. Preferred in cps mode: with Connection: close, wrk counts
# every close-delimited response as a read error and reports zero requests
# even while moving tens of megabytes.
#
# Two different measurements:
#   cps  new TLS connection per request (Connection: close). Handshake bound,
#        which is where the budget says the cost is. Needs wrk: h2load does
#        not reconnect after the server closes, so it would do one request
#        per client and report nothing.
#   rps  keepalive. Measures the relay and inspection path instead.
#
# Example, kernel build:
#   ./bench_proxy.sh -t origin.test.invalid:8443 -a 127.0.0.1 \
#                    -c poc_ca_kernel.pem -p poc_proxy_kernel

set -e

TARGET=""
ADDR=""
CACERT=""
PROC=""
DURATION=20
CONNS=50
MODE=cps
LOGFILE=""
NETNS=""

while [ $# -gt 0 ]; do
    case "$1" in
        -t) TARGET=$2; shift 2 ;;
        -a) ADDR=$2; shift 2 ;;
        -c) CACERT=$2; shift 2 ;;
        -p) PROC=$2; shift 2 ;;
        -d) DURATION=$2; shift 2 ;;
        -C) CONNS=$2; shift 2 ;;
        -m) MODE=$2; shift 2 ;;
        -l) LOGFILE=$2; shift 2 ;;
        -N) NETNS=$2; shift 2 ;;
        *) echo "unknown argument: $1"; exit 1 ;;
    esac
done

[ -n "${TARGET}" ] && [ -n "${ADDR}" ] && [ -n "${PROC}" ] || {
    echo "usage: $0 -t host:port -a addr -c cacert -p pid|name [-d sec] [-C conns]"
    exit 1
}

HOST=$(echo "${TARGET}" | cut -d: -f1)
PORT=$(echo "${TARGET}" | cut -d: -f2)

# Load generators have no --resolve, and the proxy keys everything on SNI, so
# an IP in the URL would arrive with no SNI at all. The name has to resolve.
if ! getent hosts "${HOST}" | grep -q "${ADDR}"; then
    echo "${HOST} does not resolve to ${ADDR}. Add it once:"
    echo
    echo "  echo '${ADDR} ${HOST}' | sudo tee -a /etc/hosts"
    echo
    echo "Neither h2load nor wrk supports --resolve, and sending an IP in the"
    echo "URL means no SNI, which this proxy rejects."
    exit 1
fi

# Resolve the process to account for. The kernel truncates comm to 15
# characters, so an exact match on a longer binary name never succeeds --
# fall back to the truncated form, then to the full command line while
# excluding this script.
case "${PROC}" in
    ''|*[!0-9]*)
        # Every one of these needs || true: pgrep exits 1 when it matches
        # nothing, and a bare failing assignment under set -e kills the
        # script before it has printed anything at all.
        matches=$(pgrep -x "${PROC}" 2>/dev/null || true)
        if [ -z "${matches}" ]; then
            # comm is truncated to 15 characters by the kernel.
            matches=$(pgrep -x "$(printf '%.15s' "${PROC}")" 2>/dev/null || true)
        fi
        if [ -z "${matches}" ]; then
            matches=$(pgrep -f "${PROC}" 2>/dev/null | grep -v "^$$\$" || true)
        fi
        count=$(echo "${matches}" | grep -c '[0-9]' 2>/dev/null || echo 0)
        # Picking one of several silently attributes CPU to whichever process
        # pgrep happened to list first -- typically a stale idle instance,
        # which reads as zero cores and zero throughput.
        if [ "${count}" -gt 1 ]; then
            echo "several processes match '${PROC}':"
            for m in ${matches}; do
                printf '  pid %-8s %s\n' "${m}" \
                    "$(tr '\0' ' ' < "/proc/${m}/cmdline" 2>/dev/null)"
            done
            echo
            echo "Kill the stale ones, or pass the pid you mean with -p <pid>."
            exit 1
        fi
        PID=$(echo "${matches}" | head -1)
        ;;
    *)  PID=${PROC} ;;
esac
[ -n "${PID}" ] && [ -r "/proc/${PID}/stat" ] || {
    echo "cannot find process '${PROC}'"; exit 1
}

# Generator choice follows the mode. Only wrk reconnects after the server
# closes the connection, so only wrk can measure a connection rate.
case "${MODE}" in
cps)
    if command -v wrk >/dev/null 2>&1; then
        GEN=wrk
    else
        echo "cps mode needs wrk, which reconnects after each close:"
        echo "  sudo apt install -y wrk"
        echo
        echo "h2load does one request per client and stops, so it cannot"
        echo "measure a connection rate. Use -m rps for a keepalive test."
        exit 1
    fi
    ;;
rps)
    if command -v h2load >/dev/null 2>&1; then
        GEN=h2load
    elif command -v wrk >/dev/null 2>&1; then
        GEN=wrk
    else
        echo "need h2load or wrk: sudo apt install -y nghttp2-client wrk"
        exit 1
    fi
    ;;
*)
    echo "mode must be cps or rps"
    exit 1
    ;;
esac

# One real request before loading: a dead origin or a stopped proxy otherwise
# produces a confident-looking table full of zeros.
if ! ${NSX} curl -sS --max-time 10 ${CACERT:+--cacert "${CACERT}"} \
        "https://${HOST}:${PORT}/" >/dev/null 2>&1; then
    echo "preflight failed: no successful request through ${TARGET}."
    echo
    echo "Check, in order:"
    echo "  - the proxy is running and listening on ${PORT}"
    echo "  - its origin is up:            ./origin.sh start"
    echo "  - the CA matches this build:   ${CACERT:-<none>}"
    echo
    echo "test_single_box.sh starts an origin and kills it on exit, so a"
    echo "functional test passing does not mean one is running now."
    exit 1
fi

# Run the generator in a namespace so client traffic crosses the rig's link
# rather than being short-circuited as local.
if [ -n "${NETNS}" ]; then
    NSX="ip netns exec ${NETNS}"
else
    NSX=""
fi

cpu_ticks() {
    # utime + stime from /proc/<pid>/stat, fields 14 and 15 after comm.
    awk '{ n = 0; for (i = 1; i <= NF; i++) if ($i ~ /\)$/) n = i;
           print $(n + 12) + $(n + 13) }' "/proc/${PID}/stat"
}

# System-wide busy jiffies. Process accounting misses softirq and ksoftirqd,
# where a kernel-stack proxy does much of its TCP work, so the true cost of
# the kernel build sits above its process figure. F-Stack does all stack work
# in process, so its process figure is essentially complete.
sys_busy() {
    awk '/^cpu / { idle = $5 + $6; total = 0;
                   for (i = 2; i <= NF; i++) total += $i;
                   print total - idle }' /proc/stat
}

HZ=$(getconf CLK_TCK)
NPROC=$(getconf _NPROCESSORS_ONLN)

echo "target     ${TARGET} via ${ADDR}"
echo "process    pid ${PID} ($(tr -d '\0' < /proc/${PID}/comm))"
echo "mode       ${MODE} ($([ "${MODE}" = cps ] && echo "new connection per request" || echo "keepalive"))"
echo "generator  ${GEN}, ${CONNS} connections, ${DURATION}s"
echo

# The proxy's own counters beat the generator's: they cannot be confused by
# connection-close semantics.
poc_sessions() {
    [ -n "${LOGFILE}" ] && [ -r "${LOGFILE}" ] || { echo ""; return; }
    grep '^\[poc\]' "${LOGFILE}" 2>/dev/null | tail -1 |
        sed -n 's/.*sessions=\([0-9]*\).*/\1/p'
}

s0=$(poc_sessions)
b0=$(sys_busy)
t0=$(cpu_ticks)
start=$(date +%s)

if [ "${MODE}" = cps ]; then
    CLOSE='-H "Connection: close"'
else
    CLOSE=''
fi

case "${GEN}" in
h2load)
    # No Connection: close here -- h2load would issue one request per client
    # and then sit idle, reporting a rate of zero.
    out=$(${NSX} h2load --h1 -c "${CONNS}" -D "${DURATION}" \
              "https://${HOST}:${PORT}/" 2>&1) || true
    rate=$(echo "${out}" | awk '/finished in/ { for (i=1;i<=NF;i++) if ($i=="req/s,") print $(i-1) }' | head -1)
    lat=$(echo "${out}" | awk '/time for request:/ { print "min "$4"  mean "$6"  max "$5 }' | head -1)
    lat="${lat}   (h2load reports mean/max, not percentiles)"
    ;;
wrk)
    if [ "${MODE}" = cps ]; then
        out=$(${NSX} wrk -t8 -c"${CONNS}" -d"${DURATION}s" --latency \
                  -H "Connection: close" \
                  "https://${HOST}:${PORT}/" 2>&1) || true
    else
        out=$(${NSX} wrk -t8 -c"${CONNS}" -d"${DURATION}s" --latency \
                  "https://${HOST}:${PORT}/" 2>&1) || true
    fi
    rate=$(echo "${out}" | awk '/Requests\/sec/ { print $2 }')
    lat=$(echo "${out}" | awk '/ 50%| 99%/ { printf "%s %s  ", $1, $2 }')
    ;;
esac

end=$(date +%s)
t1=$(cpu_ticks)
b1=$(sys_busy)
# Give the proxy a moment to emit a stats line covering the tail of the run.
[ -n "${LOGFILE}" ] && sleep 6
s1=$(poc_sessions)

wall=$((end - start))
[ "${wall}" -lt 1 ] && wall=1
ticks=$((t1 - t0))
cpu_ms=$((ticks * 1000 / HZ))
cores=$(awk -v ms="${cpu_ms}" -v w="${wall}" 'BEGIN { printf "%.2f", ms / 1000 / w }')

echo "${out}" | tail -20
echo
echo "---- accounting ----------------------------------------------"

# The proxy's session counter is authoritative for cps, where the generator
# cannot account for close-delimited responses. Under keepalive it counts
# almost nothing -- connections are reused -- so rps must come from the
# generator, which handles that case correctly.
if [ "${MODE}" = cps ] && [ -n "${s0}" ] && [ -n "${s1}" ] && \
   [ "${s1}" -gt "${s0}" ]; then
    sessions=$((s1 - s0))
    rate=$(awk -v n="${sessions}" -v w="${wall}" 'BEGIN { printf "%.1f", n / w }')
    printf 'connections/s      %s   (from the proxy: %s sessions in %ss)\n' \
        "${rate}" "${sessions}" "${wall}"
else
    printf 'connections/s      %s   (generator reported)\n' "${rate:-unknown}"
    if [ "${MODE}" = cps ]; then
        echo '                   note: in cps mode wrk counts close-delimited'
        echo '                   responses as read errors and reports zero.'
        echo '                   Pass -l <proxy log> for an authoritative count.'
    fi
fi
if [ "${MODE}" = cps ]; then
    printf 'latency            not meaningful in cps mode -- use -m rps\n'
else
    printf 'latency            %s\n' "${lat:-unknown}"
fi
printf 'proxy cpu          %s s over %s s wall\n' "$((cpu_ms / 1000))" "${wall}"
printf 'proxy cores        %s of %s\n' "${cores}" "${NPROC}"
sys_cores=$(awk -v d="$((b1 - b0))" -v hz="${HZ}" -v w="${wall}" \
    'BEGIN { printf "%.2f", d / hz / w }')
printf 'system busy cores  %s   (includes the generator and origin)\n' "${sys_cores}"
if [ -n "${rate}" ]; then
    printf 'cores per 1k cps   %s\n' \
        "$(awk -v c="${cores}" -v r="${rate}" 'BEGIN { if (r > 0) printf "%.3f", c * 1000 / r; else print "n/a" }')"
fi
echo
printf 'RESULT cps=%s cores=%s sys_cores=%s per1k=%s conns=%s mode=%s\n' \
    "${rate:-0}" "${cores}" "${sys_cores}" \
    "$(awk -v c="${cores}" -v r="${rate:-0}" 'BEGIN { if (r > 0) printf "%.3f", c * 1000 / r; else print "0" }')" \
    "${CONNS}" "${MODE}"

cat <<'NOTE'

Reading these numbers
  Compared proxies must do equivalent work -- TLS termination, an upstream
  TLS connection, and the same inspection. Passthrough proves nothing.

  Process CPU undercounts a kernel-stack proxy: softirq and ksoftirqd are
  not charged to it. System busy cores overcounts, since the generator and
  origin share this box. The truth is between them.

  Do NOT compare F-Stack to the kernel on CPU at fixed load. With
  idle_sleep=0 an F-Stack worker spins, burning a full core at any load, so
  the figure is meaningless. Pin each side to N cores instead -- taskset for
  the kernel build, lcore_mask for F-Stack -- push until the latency budget
  breaks, and compare maximum CPS at equal core count. Cores at fixed load
  is the right metric only between two event-driven proxies, such as the
  kernel build against Envoy.
NOTE
