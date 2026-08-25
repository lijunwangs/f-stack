#!/bin/sh
# Symmetric test rig: both stacks reach the same peers over the same veth
# pair, so the transport is the only difference between runs.
#
#            root namespace                    netns poc_peer
#   proxy  --  poc_host  <==== veth ====>  poc_peer0  --  wrk + nginx
#              10.97.0.2                    10.97.0.1
#
# A namespace is required: an address on a veth in the same namespace is
# still local, so the kernel would deliver via lo and never touch the veth.
#
#   ./rig.sh up kernel     poc_host keeps the address; the kernel proxy binds it
#   ./rig.sh up fstack     poc_host has no address; DPDK owns it via af_packet
#   ./rig.sh down
#
# NOTE: with af_packet, F-Stack's packets still traverse the kernel's packet
# path, so this rig cannot show F-Stack at its best. Only a physical NIC bound
# to vfio-pci can. Treat results here as directional and biased against
# F-Stack -- a win despite the handicap is meaningful, a loss is not.

set -e

NS=${NS:-poc_peer}
HOST_IF=${HOST_IF:-poc_host}
PEER_IF=${PEER_IF:-poc_peer0}
# Deliberately NOT 10.98.0.x: that belongs to the virtio link. Overlapping
# subnets put the F-Stack address on a local veth, so traffic meant for it is
# delivered locally and the proxy never sees a packet.
HOST_IP=${HOST_IP:-10.97.0.2}
PEER_IP=${PEER_IP:-10.97.0.1}
PREFIX=24
DIR=$(cd "$(dirname "$0")" && pwd)
TEST_HOST=${TEST_HOST:-origin.test.invalid}
ORIGIN_PORT=${ORIGIN_PORT:-9443}

nsx() { ip netns exec "${NS}" "$@"; }

case "${1:-}" in
up)
    MODE=${2:-kernel}

    ip netns add "${NS}" 2>/dev/null || true
    if ! ip link show "${HOST_IF}" >/dev/null 2>&1; then
        ip link add "${HOST_IF}" type veth peer name "${PEER_IF}"
        ip link set "${PEER_IF}" netns "${NS}"
    fi

    # Offloads off on both ends: on a local pair the kernel leaves TCP
    # checksums partial, which F-Stack drops. Off for both runs so the stack
    # is the only variable.
    ethtool -K "${HOST_IF}" tx off rx off gso off tso off gro off >/dev/null 2>&1 || true
    nsx ethtool -K "${PEER_IF}" tx off rx off gso off tso off gro off >/dev/null 2>&1 || true

    nsx ip addr replace "${PEER_IP}/${PREFIX}" dev "${PEER_IF}"
    nsx ip link set "${PEER_IF}" up
    nsx ip link set lo up
    ip link set "${HOST_IF}" up

    if [ "${MODE}" = kernel ]; then
        ip addr replace "${HOST_IP}/${PREFIX}" dev "${HOST_IF}"
        echo "rig up for the kernel build: proxy binds ${HOST_IP} on ${HOST_IF}"
    else
        ip addr flush dev "${HOST_IF}" 2>/dev/null || true
        echo "rig up for F-Stack: ${HOST_IF} has no kernel address"
        echo "  config.ini: addr=${HOST_IP} gateway=${PEER_IP}"
        echo "  extra_eal_args=--vdev=net_af_packet0,iface=${HOST_IF} --no-pci"
    fi

    # Origin inside the namespace, so proxy-to-origin traffic crosses the veth
    # in the same way client-to-proxy does. Tagged "ns" so it does not share a
    # config or pidfile with an origin serving the virtio link.
    nsx "${DIR}/origin.sh" stop "${PEER_IP}" "${ORIGIN_PORT}" ns >/dev/null 2>&1 || true
    nsx "${DIR}/origin.sh" start "${PEER_IP}" "${ORIGIN_PORT}" ns || {
        echo "warning: origin did not start inside ${NS}"
    }

    echo
    echo "origin  ${PEER_IP}:${ORIGIN_PORT}   (inside netns ${NS})"
    echo "proxy   ${HOST_IP}:8443"
    echo "load    ip netns exec ${NS} wrk ...   or bench_proxy.sh -N ${NS}"
    echo
    echo "compare with:  sudo B_ADDR=${HOST_IP} B_NS=${NS} ./compare.sh"
    grep -q "${HOST_IP} ${TEST_HOST}" /etc/hosts 2>/dev/null || {
        echo
        echo "add the name once:  echo '${HOST_IP} ${TEST_HOST}' | sudo tee -a /etc/hosts"
    }
    ;;
down)
    nsx "${DIR}/origin.sh" stop "${PEER_IP}" "${ORIGIN_PORT}" ns >/dev/null 2>&1 || true
    ip netns pids "${NS}" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip link del "${HOST_IF}" 2>/dev/null || true
    ip netns del "${NS}" 2>/dev/null || true
    echo "rig down"
    ;;
status)
    echo "root:"; ip -br addr show "${HOST_IF}" 2>/dev/null || echo "  ${HOST_IF} absent"
    echo "netns ${NS}:"; nsx ip -br addr show "${PEER_IF}" 2>/dev/null || echo "  absent"
    ;;
*)
    echo "usage: $0 {up kernel|up fstack|down|status}"
    exit 1
    ;;
esac
