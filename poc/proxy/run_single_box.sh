#!/bin/sh
# Single-box POC runner: origin, gateway and client all on one host, over a
# TAP link. No physical NIC, no public address, no outbound connectivity.
#
# Usage: ./run_single_box.sh   (as root, or with sudo for the ip commands)
set -e

TAP=ffm0
KERNEL_IP=10.99.0.1
FSTACK_IP=10.99.0.2
GW_PORT=8443
ORIGIN_PORT=9443
TEST_HOST=origin.test.invalid

echo "1. generating an origin certificate for ${TEST_HOST}"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout origin_key.pem -out origin_crt.pem -days 1 -nodes \
    -subj "/CN=${TEST_HOST}" -addext "subjectAltName=DNS:${TEST_HOST}" \
    >/dev/null 2>&1

echo "2. starting the origin on the kernel side (${KERNEL_IP}:${ORIGIN_PORT})"
openssl s_server -quiet -accept "${KERNEL_IP}:${ORIGIN_PORT}" \
    -cert origin_crt.pem -key origin_key.pem -www &
ORIGIN_PID=$!
trap 'kill ${ORIGIN_PID} 2>/dev/null || true' EXIT

echo "3. starting the gateway (F-Stack side ${FSTACK_IP}:${GW_PORT})"
echo "   in another shell, once ${TAP} appears:"
echo "     sudo ip addr add ${KERNEL_IP}/24 dev ${TAP}"
echo "     sudo ip link set ${TAP} up"
echo
echo "4. then drive it, using --resolve so that SNI is sent:"
echo "     curl -v --cacert poc_ca.pem \\"
echo "          --resolve ${TEST_HOST}:${GW_PORT}:${FSTACK_IP} \\"
echo "          https://${TEST_HOST}:${GW_PORT}/"
echo
echo "   and check that the scan fires:"
echo "     curl --cacert poc_ca.pem \\"
echo "          --resolve ${TEST_HOST}:${GW_PORT}:${FSTACK_IP} \\"
echo "          -d 'x=SECRET-CANARY' https://${TEST_HOST}:${GW_PORT}/"
echo

POC_ORIGIN="${KERNEL_IP}:${ORIGIN_PORT}" \
POC_LISTEN_PORT="${GW_PORT}" \
POC_PATTERN="SECRET-CANARY" \
./poc_proxy --conf config.ini --proc-type=primary
