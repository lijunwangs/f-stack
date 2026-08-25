#!/bin/sh
# Measure a running proxy under fixed load and report cores consumed.
#
# The metric is CPU per unit of work, not peak throughput: "who tuned harder"
# is an unwinnable argument, while cores per 1000 CPS is what a capacity plan
# actually uses. Works against either build, and against Envoy or any other
# proxy -- point it at a host:port and give it the process to account for.
#
#   ./bench_proxy.sh -t <host>:<port> -a <resolve-addr> -c <cacert> \
#                    -p <pid|name> [-d seconds] [-C connections]
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

while [ $# -gt 0 ]; do
    case "$1" in
        -t) TARGET=$2; shift 2 ;;
        -a) ADDR=$2; shift 2 ;;
        -c) CACERT=$2; shift 2 ;;
        -p) PROC=$2; shift 2 ;;
        -d) DURATION=$2; shift 2 ;;
        -C) CONNS=$2; shift 2 ;;
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
        PID=$(pgrep -x "${PROC}" 2>/dev/null | head -1)
        if [ -z "${PID}" ]; then
            PID=$(pgrep -x "$(printf '%.15s' "${PROC}")" 2>/dev/null | head -1)
        fi
        if [ -z "${PID}" ]; then
            PID=$(pgrep -f "${PROC}" 2>/dev/null | grep -v "^$$\$" | head -1)
        fi
        ;;
    *)  PID=${PROC} ;;
esac
[ -n "${PID}" ] && [ -r "/proc/${PID}/stat" ] || {
    echo "cannot find process '${PROC}'"; exit 1
}

# Pick a generator. h2load and wrk both report percentiles and can be told to
# open a fresh connection per request, which is what makes this a CPS test.
if command -v h2load >/dev/null 2>&1; then
    GEN=h2load
elif command -v wrk >/dev/null 2>&1; then
    GEN=wrk
else
    echo "need h2load (nghttp2-client) or wrk:"
    echo "  sudo apt install -y nghttp2-client"
    exit 1
fi

cpu_ticks() {
    # utime + stime from /proc/<pid>/stat, fields 14 and 15 after comm.
    awk '{ n = 0; for (i = 1; i <= NF; i++) if ($i ~ /\)$/) n = i;
           print $(n + 12) + $(n + 13) }' "/proc/${PID}/stat"
}

HZ=$(getconf CLK_TCK)
NPROC=$(getconf _NPROCESSORS_ONLN)

echo "target     ${TARGET} via ${ADDR}"
echo "process    pid ${PID} ($(tr -d '\0' < /proc/${PID}/comm))"
echo "generator  ${GEN}, ${CONNS} connections, ${DURATION}s"
echo

t0=$(cpu_ticks)
start=$(date +%s)

case "${GEN}" in
h2load)
    # --h1 keeps it HTTP/1.1; Connection: close forces a new TLS handshake
    # per request, so requests/s is the connection rate.
    # h2load does not verify the peer certificate, so ${CACERT} is unused
    # here; the functional test already proved verification works.
    out=$(h2load --h1 -c "${CONNS}" -D "${DURATION}" \
              -H "Connection: close" \
              "https://${HOST}:${PORT}/" 2>&1) || true
    rate=$(echo "${out}" | awk '/finished in/ { for (i=1;i<=NF;i++) if ($i=="req/s,") print $(i-1) }' | head -1)
    # "time for request:   min  max  mean  sd  +/- sd"
    lat=$(echo "${out}" | awk '/time for request:/ { print "min "$4"  mean "$6"  max "$5 }' | head -1)
    lat="${lat}   (h2load reports mean/max, not percentiles -- use wrk for tails)"
    ;;
wrk)
    out=$(wrk -t4 -c"${CONNS}" -d"${DURATION}s" --latency \
              -H "Connection: close" \
              "https://${HOST}:${PORT}/" 2>&1) || true
    rate=$(echo "${out}" | awk '/Requests\/sec/ { print $2 }')
    lat=$(echo "${out}" | awk '/50%|99%/ { printf "%s %s  ", $1, $2 }')
    ;;
esac

end=$(date +%s)
t1=$(cpu_ticks)

wall=$((end - start))
[ "${wall}" -lt 1 ] && wall=1
ticks=$((t1 - t0))
cpu_ms=$((ticks * 1000 / HZ))
cores=$(awk -v ms="${cpu_ms}" -v w="${wall}" 'BEGIN { printf "%.2f", ms / 1000 / w }')

echo "${out}" | tail -20
echo
echo "---- accounting ----------------------------------------------"
printf 'connections/s      %s\n' "${rate:-unknown}"
printf 'latency            %s\n' "${lat:-unknown}"
printf 'proxy cpu          %s s over %s s wall\n' "$((cpu_ms / 1000))" "${wall}"
printf 'proxy cores        %s of %s\n' "${cores}" "${NPROC}"
if [ -n "${rate}" ]; then
    printf 'cores per 1k cps   %s\n' \
        "$(awk -v c="${cores}" -v r="${rate}" 'BEGIN { if (r > 0) printf "%.3f", c * 1000 / r; else print "n/a" }')"
fi
echo
echo "Report cores per 1k cps and the tail latency together. A rate difference"
echo "alone says nothing without the CPU it cost, and neither means anything"
echo "unless the compared proxies are doing equivalent work: TLS termination,"
echo "an upstream TLS connection, and the same inspection."
