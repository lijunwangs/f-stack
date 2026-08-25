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
# LINK_MODE=veth   veth pair + af_packet PMD (packets still cross the kernel)
# LINK_MODE=virtio virtio_user + vhost-net: a real DPDK datapath, so this is
#                  the mode to measure on when no physical NIC is available.
LINK_MODE=${LINK_MODE:-veth}
HOST_IF=${HOST_IF:-ffhost}
DPDK_IF=${DPDK_IF:-ffdpdk}
KERNEL_IP=${KERNEL_IP:-10.99.0.1}
VIRTIO_IF=${VIRTIO_IF:-ffvu0}
VIRTIO_KERNEL_IP=${VIRTIO_KERNEL_IP:-10.98.0.1}
# Must differ from the mac= on the vdev: DPDK stamps the port's MAC onto the
# tap it creates, and FreeBSD's ARP drops any request whose sender MAC is its
# own (freebsd/netinet/if_ether.c:899).
VIRTIO_KERNEL_MAC=${VIRTIO_KERNEL_MAC:-00:16:3e:5a:00:01}

# The origin lives on the kernel side of whichever link is in use, so the
# default has to follow LINK_MODE or the proxy dials the wrong network.
if [ "${LINK_MODE}" = virtio ]; then
    POC_ORIGIN=${POC_ORIGIN:-${VIRTIO_KERNEL_IP}:9443}
else
    POC_ORIGIN=${POC_ORIGIN:-${KERNEL_IP}:9443}
fi
POC_LISTEN_PORT=${POC_LISTEN_PORT:-8443}
POC_PATTERN=${POC_PATTERN:-SECRET-CANARY}
export POC_ORIGIN POC_LISTEN_PORT POC_PATTERN

running() {
    [ -f "${PIDFILE}" ] && kill -0 "$(cat "${PIDFILE}")" 2>/dev/null
}

# af_packet binds a raw socket at EAL init, so the pair must exist and be up
# before the gateway starts. Idempotent.
# vhost-net creates the kernel-side interface during EAL init, so it can only
# be configured after the gateway starts.
setup_virtio_link() {
    i=0
    while ! ip link show "${VIRTIO_IF}" >/dev/null 2>&1; do
        i=$((i + 1))
        [ "${i}" -gt 20 ] && {
            echo "warning: ${VIRTIO_IF} never appeared -- is vhost_net loaded?"
            return 1
        }
        sleep 1
    done
    # Re-stamp the kernel side before bringing it up. DPDK gave the tap the
    # same MAC as the virtio port, which makes every ARP request look
    # self-originated to F-Stack and get dropped silently.
    ip link set "${VIRTIO_IF}" down 2>/dev/null || true
    ip link set "${VIRTIO_IF}" address "${VIRTIO_KERNEL_MAC}"
    ip addr replace "${VIRTIO_KERNEL_IP}/24" dev "${VIRTIO_IF}"
    ip link set "${VIRTIO_IF}" up
    ethtool -K "${VIRTIO_IF}" tx off rx off gso off tso off gro off \
        >/dev/null 2>&1 || true
    echo "link: ${VIRTIO_IF} (kernel, ${VIRTIO_KERNEL_IP}, ${VIRTIO_KERNEL_MAC})"
    echo "      <-> virtio_user (DPDK, MAC from config.ini extra_eal_args)"
}

setup_link() {
    if [ "${LINK_MODE}" = virtio ]; then
        modprobe vhost_net 2>/dev/null || true
        [ -c /dev/vhost-net ] || echo "warning: /dev/vhost-net missing"
        return 0
    fi
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
    if [ "${LINK_MODE}" = virtio ]; then
        setup_virtio_link
    else
        echo "link: ${HOST_IF} (kernel, ${KERNEL_IP}) <-> ${DPDK_IF} (DPDK)"
    fi
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
