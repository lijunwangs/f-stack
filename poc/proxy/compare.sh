#!/bin/sh
# Saturation comparison between two proxies at equal core count.
#
# For a busy-polling stack, CPU at fixed load is meaningless -- an F-Stack
# worker spins at 100% whatever the offered load. So this sweeps concurrency
# until the connection rate stops climbing and reports the plateau: maximum
# sustained CPS per core. Both sides must be pinned to the same number of
# cores for the comparison to mean anything.
#
#   sudo ./compare.sh
#
# Configure through the environment; defaults match the POC's own rigs.
#
#   A_* is side A (F-Stack over virtio_user by default)
#   B_* is side B (the kernel build)
#
# Each side must already be running, pinned to one core:
#   sudo LINK_MODE=virtio ./poc_ctl.sh start
#   taskset -c 4 env POC_ORIGIN=10.98.0.1:9443 POC_LISTEN_PORT=8444 \
#       POC_CA_OUT=poc_ca_kernel.pem ./poc_proxy_kernel > poc_kernel.log 2>&1 &

set -e

A_NAME=${A_NAME:-fstack}
A_HOST=${A_HOST:-a.test.invalid}
A_ADDR=${A_ADDR:-10.98.0.2}
A_PORT=${A_PORT:-8443}
A_CA=${A_CA:-poc_ca.pem}
A_PROC=${A_PROC:-poc_proxy}
A_LOG=${A_LOG:-poc_proxy.log}
A_NS=${A_NS:-}

B_NAME=${B_NAME:-kernel}
B_HOST=${B_HOST:-b.test.invalid}
B_ADDR=${B_ADDR:-127.0.0.1}
B_PORT=${B_PORT:-8444}
B_CA=${B_CA:-poc_ca_kernel.pem}
B_PROC=${B_PROC:-poc_proxy_kernel}
B_LOG=${B_LOG:-poc_kernel.log}
B_NS=${B_NS:-}

SWEEP=${SWEEP:-"25 50 100 200 400"}
DUR=${DUR:-30}
# Stop only after this many consecutive steps fail to beat the best seen.
# One non-improving step is not a plateau: throughput often dips when the
# generator starts contending, then recovers.
STALL_STEPS=${STALL_STEPS:-2}
OUT=${OUT:-compare_results.txt}
DIR=$(cd "$(dirname "$0")" && pwd)

# Command substitution swallows stdout, so keep a handle on the terminal for
# diagnostics that must be seen while a step is running.
exec 3>&1

# Check the NAME resolves to the address. Testing whether a line starts with
# the address is wrong: /etc/hosts already has "127.0.0.1 localhost", which
# would pass for any name pointed at 127.0.0.1.
need_host() {
    _addr=$1; _name=$2
    if getent hosts "${_name}" 2>/dev/null | grep -q "^${_addr}[[:space:]]"; then
        echo "  ${_name} -> ${_addr}"
        return 0
    fi
    if [ -w /etc/hosts ]; then
        printf '%s %s\n' "${_addr}" "${_name}" >> /etc/hosts
        echo "  ${_name} -> ${_addr}  (added to /etc/hosts)"
    else
        echo "  ${_name} does not resolve to ${_addr}; run as root or add:"
        echo "    echo '${_addr} ${_name}' | sudo tee -a /etc/hosts"
        return 1
    fi
}

# One sweep step. Echoes "cps cores per1k" or nothing on failure.
run_step() {
    _host=$1; _port=$2; _addr=$3; _ca=$4; _proc=$5; _log=$6; _ns=$7; _c=$8; _mode=$9
    out=$("${DIR}/bench_proxy.sh" -t "${_host}:${_port}" -a "${_addr}" \
              -c "${_ca}" -p "${_proc}" -l "${_log}" -m "${_mode}" \
              -d "${DUR}" -C "${_c}" ${_ns:+-N "${_ns}"} 2>&1) || true
    result=$(echo "${out}" | awk '/^RESULT/ {
        for (i = 2; i <= NF; i++) { split($i, kv, "="); v[kv[1]] = kv[2] }
        print v["cps"], v["cores"], v["per1k"]
    }' | tail -1)
    _cps=$(echo "${result}" | awk '{ print ($1 == "" ? 0 : $1) }')
    if [ -z "${result}" ] || awk -v n="${_cps}" 'BEGIN { exit !(n + 0 <= 0) }'; then
        # Either bench_proxy bailed or it measured nothing. Show the command
        # and its output on stdout -- on stderr this got separated from the
        # captured stream and the failure looked unexplained.
        {
            echo "           ---- step produced no rate; command was:"
            echo "           ${DIR}/bench_proxy.sh -t ${_host}:${_port}" \
                 "-a ${_addr} -c ${_ca} -p ${_proc} -l ${_log}" \
                 "-m ${_mode} -d ${DUR} -C ${_c}"
            if [ -n "${out}" ]; then
                echo "${out}" | grep -vE '^[[:space:]]*$' | tail -12 |
                    sed 's/^/           | /'
            else
                echo "           | (no output at all from bench_proxy.sh)"
            fi
            echo "           ----"
        } >&3
    fi
    echo "${result}"
}

# Sweep concurrency and keep the best result. Sets SAT_CPS / SAT_C / SAT_CORES.
saturate() {
    _label=$1; shift
    best=0; best_c=0; best_cores=0; stalled=0
    for c in ${SWEEP}; do
        printf '  %-8s C=%-4s ' "${_label}" "${c}"
        r=$(run_step "$1" "$2" "$3" "$4" "$5" "$6" "$7" "${c}" cps)
        cps=$(echo "${r}" | awk '{ print ($1 == "" ? 0 : $1) }')
        cores=$(echo "${r}" | awk '{ print ($2 == "" ? 0 : $2) }')
        printf 'cps=%-9s cores=%s\n' "${cps}" "${cores}"

        # A zero rate is a broken run, not a slow one. Say so and stop.
        dead=$(awk -v n="${cps}" 'BEGIN { print (n + 0 <= 0) ? 1 : 0 }')
        if [ -z "${r}" ] || [ "${dead}" = 1 ]; then
            echo "           no traffic measured -- diagnostics above; stopping"
            break
        fi

        better=$(awk -v n="${cps}" -v o="${best}" 'BEGIN { print (n > o) ? 1 : 0 }')
        if [ "${better}" = 1 ]; then
            best=${cps}; best_c=${c}; best_cores=${cores}; stalled=0
        else
            stalled=$((stalled + 1))
            if [ "${stalled}" -ge "${STALL_STEPS}" ]; then
                echo "           ${stalled} steps without improvement; peak was ${best} at C=${best_c}"
                break
            fi
        fi
    done
    SAT_CPS=${best}; SAT_C=${best_c}; SAT_CORES=${best_cores}
}

echo "names"
need_host "${A_ADDR}" "${A_HOST}" || exit 1
need_host "${B_ADDR}" "${B_HOST}" || exit 1

echo
echo "saturation sweep (${DUR}s per step, stop after ${STALL_STEPS} steps without improvement)"
saturate "${A_NAME}" "${A_HOST}" "${A_PORT}" "${A_ADDR}" "${A_CA}" \
         "${A_PROC}" "${A_LOG}" "${A_NS}"
A_CPS=${SAT_CPS}; A_C=${SAT_C}; A_CORES=${SAT_CORES}

saturate "${B_NAME}" "${B_HOST}" "${B_PORT}" "${B_ADDR}" "${B_CA}" \
         "${B_PROC}" "${B_LOG}" "${B_NS}"
B_CPS=${SAT_CPS}; B_C=${SAT_C}; B_CORES=${SAT_CORES}

echo
echo "latency at half the plateau concurrency (keepalive)"
A_HALF=$(awk -v c="${A_C}" 'BEGIN { printf "%d", (c / 2 < 1 ? 1 : c / 2) }')
B_HALF=$(awk -v c="${B_C}" 'BEGIN { printf "%d", (c / 2 < 1 ? 1 : c / 2) }')
A_LAT=$(run_step "${A_HOST}" "${A_PORT}" "${A_ADDR}" "${A_CA}" "${A_PROC}" \
                 "${A_LOG}" "${A_NS}" "${A_HALF}" rps)
B_LAT=$(run_step "${B_HOST}" "${B_PORT}" "${B_ADDR}" "${B_CA}" "${B_PROC}" \
                 "${B_LOG}" "${B_NS}" "${B_HALF}" rps)
printf '  %-8s rps=%s\n' "${A_NAME}" "$(echo "${A_LAT}" | awk '{ print $1 }')"
printf '  %-8s rps=%s\n' "${B_NAME}" "$(echo "${B_LAT}" | awk '{ print $1 }')"

ratio=$(awk -v a="${A_CPS}" -v b="${B_CPS}" \
    'BEGIN { if (b > 0) printf "%.2f", a / b; else print "n/a" }')

{
    echo "proxy comparison at equal core count"
    echo "date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo
    printf '%-10s %12s %10s %8s\n' side "saturation cps" "at conns" cores
    printf '%-10s %12s %10s %8s\n' "${A_NAME}" "${A_CPS}" "${A_C}" "${A_CORES}"
    printf '%-10s %12s %10s %8s\n' "${B_NAME}" "${B_CPS}" "${B_C}" "${B_CORES}"
    echo
    echo "${A_NAME} / ${B_NAME} = ${ratio}x on saturation cps"
    echo
    cat <<'CAVEAT'
Caveats to quote with these numbers
  - Both sides must be pinned to the same core count, or this compares
    core budgets rather than stacks.
  - The transports are not identical: F-Stack runs on virtio_user, the
    kernel build on veth or loopback. Each is that stack's natural fast
    virtual path, but only a physical NIC settles the question.
  - CPU is reported for reference only. A busy-polling worker spins at
    100% regardless of load, so cores per CPS is not comparable here --
    saturation CPS at equal cores is the metric.
  - The generator and origin share this box with the proxy, so absolute
    rates are floors. The ratio is the durable part.
CAVEAT
} | tee "${OUT}"

echo
echo "written to ${OUT}"
