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

HOST_IF=${HOST_IF:-ffhost}
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

echo "1. checking the link (poc_ctl.sh start creates it)"
if ! ip link show "${HOST_IF}" >/dev/null 2>&1; then
    echo "   ${HOST_IF} is missing -- run: sudo ./poc_ctl.sh start"
    exit 1
fi
ip addr replace "${KERNEL_IP}/24" dev "${HOST_IF}"
ip link set "${HOST_IF}" up

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
LOGFILE=${LOGFILE:-./poc_proxy.log}

echo
echo "5. preflight"

# Is the origin itself reachable? If not, nothing downstream can work.
if echo | timeout 10 openssl s_client -connect "${KERNEL_IP}:${ORIGIN_PORT}" \
        -servername "${TEST_HOST}" 2>/dev/null | grep -q "CONNECTED"; then
    check "origin answers directly" 1
else
    check "origin answers directly" 0
    echo "      the test origin is not reachable; the gateway cannot help"
fi

# Does the F-Stack stack respond at all? It owns ${FSTACK_IP}, so a reply
# means the TAP link is carrying packets in both directions.
if ping -c 2 -W 2 "${FSTACK_IP}" >/dev/null 2>&1; then
    check "F-Stack side answers ping" 1
    fstack_up=1
else
    check "F-Stack side answers ping" 0
    fstack_up=0
    echo "      no reply from ${FSTACK_IP}: the TAP link is not passing traffic"
fi

echo
echo "6. tests"

# The gateway must be reachable, and its leaf must chain to the POC CA with
# hostname verification on -- that is interception plus forging working.
if curl -sS --max-time 10 --cacert poc_ca.pem ${RESOLVE} \
        "https://${TEST_HOST}:${GW_PORT}/" >/dev/null 2>&1; then
    check "fetch through the gateway succeeds" 1
    baseline=1
else
    check "fetch through the gateway succeeds" 0
    baseline=0
fi

# The certificate the client sees must be ours, not the origin's. If the
# issuer is the origin itself, traffic is passing through un-intercepted.
issuer=$(echo | timeout 10 openssl s_client -connect "${FSTACK_IP}:${GW_PORT}" \
         -servername "${TEST_HOST}" 2>/dev/null |
         sed -n 's/^ *[Ii]ssuer: *//p' | head -1)
case "${issuer}" in
    *POC*CA*) check "served leaf is issued by the POC CA" 1 ;;
    *)        check "served leaf is issued by the POC CA" 0
              echo "      issuer was: ${issuer:-<none>}" ;;
esac

# Plaintext must actually reach the scanner: a body carrying the canary is
# dropped, so curl fails where the clean request above succeeded. This only
# means anything if the clean request did succeed.
if [ "${baseline}" = "1" ]; then
    if curl -sS --max-time 10 --cacert poc_ca.pem ${RESOLVE} \
            -d "x=${CANARY}" "https://${TEST_HOST}:${GW_PORT}/" >/dev/null 2>&1; then
        check "request carrying the canary is blocked" 0
    else
        check "request carrying the canary is blocked" 1
    fi
else
    printf '  %-50s skipped\n' "request carrying the canary is blocked"
    echo "      inconclusive while the clean fetch fails"
fi

echo
if [ "${fails}" = "0" ]; then
    echo "POC gate: functional path works end to end"
else
    echo "POC gate: ${fails} check(s) failed"
    if [ -f "${LOGFILE}" ]; then
        echo
        echo "last stats line:"
        grep '^\[poc\]' "${LOGFILE}" 2>/dev/null | tail -1 || echo "  (none)"
        echo "session failures reported:"
        grep 'session failed' "${LOGFILE}" 2>/dev/null | tail -5 || echo "  (none)"
    fi
    if [ "${fstack_up}" = "0" ]; then
        echo
        echo "Start here: the TAP link is not passing traffic. Check that"
        echo "poc_proxy is running, that ${TAP} is up on both sides, and that"
        echo "the log shows 'Successed to register dpdk interface'."
    fi
fi
exit "${fails}"
