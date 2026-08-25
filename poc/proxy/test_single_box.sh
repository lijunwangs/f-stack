#!/bin/sh
# End-to-end test for the POC, on one host over the TAP link.
#
# Run poc_proxy FIRST in another shell -- the TAP device only exists once
# DPDK has initialised it:
#
#   sudo POC_ORIGIN=10.99.0.1:9443 ./poc_proxy --conf config.ini --proc-type=primary
#
# Then run this script (as root: it configures the TAP and binds the origin).
set -e

TAP=${TAP:-ffm0}
KERNEL_IP=${KERNEL_IP:-10.99.0.1}
FSTACK_IP=${FSTACK_IP:-10.99.0.2}
GW_PORT=${GW_PORT:-8443}
ORIGIN_PORT=${ORIGIN_PORT:-9443}
TEST_HOST=${TEST_HOST:-origin.test.invalid}
CANARY=${CANARY:-SECRET-CANARY}
fails=0

check() {
    if [ "$2" = "1" ]; then
        printf '  %-50s ok\n' "$1"
    else
        printf '  %-50s FAIL\n' "$1"
        fails=$((fails + 1))
    fi
}

echo "1. waiting for ${TAP} (start poc_proxy first if this hangs)"
i=0
while ! ip link show "${TAP}" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -gt 30 ] && { echo "   ${TAP} never appeared -- is poc_proxy running?"; exit 1; }
    sleep 1
done

echo "2. configuring the kernel side of the link"
ip addr replace "${KERNEL_IP}/24" dev "${TAP}"
ip link set "${TAP}" up

echo "3. generating an origin certificate for ${TEST_HOST}"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout origin_key.pem -out origin_crt.pem -days 1 -nodes \
    -subj "/CN=${TEST_HOST}" -addext "subjectAltName=DNS:${TEST_HOST}" \
    >/dev/null 2>&1

echo "4. starting the origin on ${KERNEL_IP}:${ORIGIN_PORT}"
openssl s_server -quiet -accept "${KERNEL_IP}:${ORIGIN_PORT}" \
    -cert origin_crt.pem -key origin_key.pem -www >/dev/null 2>&1 &
origin_pid=$!
trap 'kill ${origin_pid} 2>/dev/null || true' EXIT
sleep 1
kill -0 ${origin_pid} 2>/dev/null || { echo "   origin failed to start"; exit 1; }

RESOLVE="--resolve ${TEST_HOST}:${GW_PORT}:${FSTACK_IP}"
echo
echo "5. tests"

# The gateway must be reachable, and its leaf must chain to the POC CA with
# hostname verification on -- that is interception plus forging working.
if curl -sS --max-time 10 --cacert poc_ca.pem ${RESOLVE} \
        "https://${TEST_HOST}:${GW_PORT}/" >/dev/null 2>&1; then
    check "fetch through the gateway succeeds" 1
else
    check "fetch through the gateway succeeds" 0
fi

# The certificate the client sees must be ours, not the origin's. If the
# issuer is the origin itself, traffic is passing through un-intercepted.
issuer=$(echo | openssl s_client -connect "${FSTACK_IP}:${GW_PORT}" \
         -servername "${TEST_HOST}" 2>/dev/null |
         sed -n 's/^ *[Ii]ssuer: *//p' | head -1)
case "${issuer}" in
    *POC*CA*) check "served leaf is issued by the POC CA" 1 ;;
    *)        check "served leaf is issued by the POC CA" 0
              echo "      issuer was: ${issuer:-<none>}" ;;
esac

# Plaintext must actually reach the scanner: a body carrying the canary is
# dropped, so curl fails where the clean request above succeeded.
if curl -sS --max-time 10 --cacert poc_ca.pem ${RESOLVE} \
        -d "x=${CANARY}" "https://${TEST_HOST}:${GW_PORT}/" >/dev/null 2>&1; then
    check "request carrying the canary is blocked" 0
else
    check "request carrying the canary is blocked" 1
fi

echo
if [ "${fails}" = "0" ]; then
    echo "POC gate: functional path works end to end"
else
    echo "POC gate: ${fails} check(s) failed -- see the poc_proxy stats line"
fi
exit "${fails}"
