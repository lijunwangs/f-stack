#!/bin/sh
# Start, stop and inspect the POC gateway as a background process.
# Must run as root: DPDK needs hugepages and the TAP device needs CAP_NET_ADMIN.
#
#   sudo ./poc_ctl.sh start     # background, logs to poc_proxy.log
#   sudo ./poc_ctl.sh status
#   sudo ./poc_ctl.sh log       # follow the log
#   sudo ./poc_ctl.sh stop

set -e

PIDFILE=${PIDFILE:-./poc_proxy.pid}
LOGFILE=${LOGFILE:-./poc_proxy.log}
CONF=${CONF:-config.ini}
HOST_IF=${HOST_IF:-ffhost}
DPDK_IF=${DPDK_IF:-ffdpdk}
KERNEL_IP=${KERNEL_IP:-10.99.0.1}

POC_ORIGIN=${POC_ORIGIN:-10.99.0.1:9443}
POC_LISTEN_PORT=${POC_LISTEN_PORT:-8443}
POC_PATTERN=${POC_PATTERN:-SECRET-CANARY}
export POC_ORIGIN POC_LISTEN_PORT POC_PATTERN

running() {
    [ -f "${PIDFILE}" ] && kill -0 "$(cat "${PIDFILE}")" 2>/dev/null
}

# af_packet binds a raw socket at EAL init, so the pair must exist and be up
# before the gateway starts. Idempotent.
setup_link() {
    if ! ip link show "${DPDK_IF}" >/dev/null 2>&1; then
        ip link add "${HOST_IF}" type veth peer name "${DPDK_IF}"
    fi
    ip addr replace "${KERNEL_IP}/24" dev "${HOST_IF}"
    ip link set "${HOST_IF}" up
    ip link set "${DPDK_IF}" up

    # Critical for veth: the kernel leaves TCP checksums as CHECKSUM_PARTIAL
    # on a local pair, so the field carries a pseudo-header sum rather than a
    # valid checksum. F-Stack validates in software and drops the segment, and
    # since ICMP is always checksummed in software, ping works while TCP dies
    # silently. Turning offloads off forces real checksums. Segmentation
    # offloads go too, so F-Stack never sees an oversized frame.
    for i in "${HOST_IF}" "${DPDK_IF}"; do
        ethtool -K "$i" tx off rx off gso off tso off gro off >/dev/null 2>&1 || \
            echo "warning: could not disable offloads on $i (is ethtool installed?)"
    done
}

case "${1:-}" in
start)
    if running; then
        echo "already running as pid $(cat "${PIDFILE}")"
        exit 0
    fi
    [ -f "${CONF}" ] || { echo "no ${CONF} -- cp config.ini.sample ${CONF}"; exit 1; }
    [ -x ./poc_proxy ] || { echo "./poc_proxy not built"; exit 1; }

    # A previous unclean exit can leave DPDK runtime state behind, which makes
    # the next EAL init fail on a stale socket.
    if [ ! -d /var/run/dpdk/rte ] || ! running; then
        rm -rf /var/run/dpdk/rte 2>/dev/null || true
    fi

    setup_link
    : > "${LOGFILE}"
    setsid ./poc_proxy --conf "${CONF}" --proc-type=primary \
        >> "${LOGFILE}" 2>&1 &
    echo $! > "${PIDFILE}"
    sleep 3

    if ! running; then
        echo "failed to start; last lines of ${LOGFILE}:"
        tail -20 "${LOGFILE}"
        rm -f "${PIDFILE}"
        exit 1
    fi
    echo "started as pid $(cat "${PIDFILE}"), logging to ${LOGFILE}"
    echo "link: ${HOST_IF} (kernel, ${KERNEL_IP}) <-> ${DPDK_IF} (DPDK)"
    echo "next: sudo ./test_single_box.sh"
    ;;

link)
    setup_link
    ip -br addr show "${HOST_IF}"
    ip -br addr show "${DPDK_IF}"
    ;;

stop)
    if ! running; then
        echo "not running"
        rm -f "${PIDFILE}"
        exit 0
    fi
    pid=$(cat "${PIDFILE}")
    kill "${pid}" 2>/dev/null || true
    i=0
    while kill -0 "${pid}" 2>/dev/null; do
        i=$((i + 1))
        [ "${i}" -gt 10 ] && { kill -9 "${pid}" 2>/dev/null || true; break; }
        sleep 1
    done
    rm -f "${PIDFILE}"
    rm -rf /var/run/dpdk/rte 2>/dev/null || true
    echo "stopped"
    ;;

status)
    if running; then
        echo "running as pid $(cat "${PIDFILE}")"
    else
        echo "not running"
    fi
    printf '%s: ' "${HOST_IF}"
    ip -br addr show "${HOST_IF}" 2>/dev/null || echo "absent"
    echo "last stats line:"
    grep '^\[poc\]' "${LOGFILE}" 2>/dev/null | tail -1 || echo "  (none yet)"
    ;;

log)
    tail -f "${LOGFILE}"
    ;;

*)
    echo "usage: $0 {start|stop|status|log|link}"
    exit 1
    ;;
esac
