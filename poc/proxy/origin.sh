#!/bin/sh
# Persistent test origin for benchmarking, on the kernel side of whatever
# link is in use. The functional test starts its own and tears it down, which
# is fine for a single request and useless for load.
#
#   ./origin.sh start [addr] [port] [tag]
#   ./origin.sh stop  [addr] [port] [tag]
#
# Prefers nginx: openssl s_server is single threaded and becomes the
# bottleneck long before the proxy does.

set -e

DIR=$(cd "$(dirname "$0")" && pwd)
ADDR=${2:-127.0.0.1}
PORT=${3:-9443}
# A tag keeps instances apart: the veth rig runs one inside a namespace while
# another serves the virtio link, and a shared conf or pidfile would collide.
TAG=${4:-root}
# `stop` takes the same optional [addr] [port]; the port is what matters,
# since the listener may be bound to any local address.
HOSTNAME_CN=${TEST_HOST:-origin.test.invalid}
CONF="${DIR}/origin_nginx_${TAG}.conf"
PIDFILE="${DIR}/origin_nginx_${TAG}.pid"

gen_cert() {
    [ -r "${DIR}/origin_crt.pem" ] && [ -r "${DIR}/origin_key.pem" ] && return 0
    rm -f "${DIR}/origin_crt.pem" "${DIR}/origin_key.pem"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${DIR}/origin_key.pem" -out "${DIR}/origin_crt.pem" \
        -days 1 -nodes -subj "/CN=${HOSTNAME_CN}" \
        -addext "subjectAltName=DNS:${HOSTNAME_CN}" 2>/dev/null
}

write_conf() {
    cat > "${CONF}" <<CONFEOF
worker_processes 4;
worker_rlimit_nofile 65535;
daemon on;
pid ${PIDFILE};
error_log ${DIR}/origin_nginx_error.log warn;
events { worker_connections 8192; }
http {
    access_log off;
    client_body_temp_path ${DIR}/nginx_tmp/${TAG}/body;
    proxy_temp_path ${DIR}/nginx_tmp/${TAG}/proxy;
    fastcgi_temp_path ${DIR}/nginx_tmp/${TAG}/fastcgi;
    uwsgi_temp_path ${DIR}/nginx_tmp/${TAG}/uwsgi;
    scgi_temp_path ${DIR}/nginx_tmp/${TAG}/scgi;
    keepalive_timeout 65;
    server {
        listen ${ADDR}:${PORT} ssl reuseport;
        ssl_certificate ${DIR}/origin_crt.pem;
        ssl_certificate_key ${DIR}/origin_key.pem;
        ssl_session_cache shared:o:10m;
        location / {
            add_header Content-Type text/plain;
            return 200 "origin ok\n";
        }
    }
}
CONFEOF
    mkdir -p "${DIR}/nginx_tmp/${TAG}"
}

# Is the port bound at all? Visible without privilege, unlike the owning pid.
port_in_use() {
    ss -H -tln 2>/dev/null | awk -v p=":${PORT}" '$4 ~ p"$" { found = 1 }
        END { exit !found }'
}

# A listener we can see but not attribute means it belongs to another user --
# typically root, from an earlier sudo run. Without this the script silently
# kills nothing and the next start fails to bind.
warn_unattributable() {
    if port_in_use && [ -z "$(port_holders)" ]; then
        echo "port ${PORT} is in use by a process this user cannot see."
        echo "It probably belongs to root, from an earlier sudo run."
        echo "Re-run with sudo, or find it with: sudo ss -tlnp | grep ${PORT}"
        return 1
    fi
    return 0
}

# Every pid listening on the port, whatever local address it bound.
port_holders() {
    ss -H -tlnp 2>/dev/null | awk -v p=":${PORT}" '
        $4 ~ p"$" { while (match($0, /pid=[0-9]+/)) {
            print substr($0, RSTART + 4, RLENGTH - 4)
            $0 = substr($0, RSTART + RLENGTH) } }' | sort -u
}

case "${1:-}" in
start)
    warn_unattributable || exit 1
    holders=$(port_holders)
    if [ -n "${holders}" ]; then
        echo "port ${PORT} is already held:"
        for h in ${holders}; do
            printf '  pid %-8s %s\n' "${h}" \
                "$(tr '\0' ' ' < "/proc/${h}/cmdline" 2>/dev/null)"
        done
        echo
        echo "Run '$0 stop' first -- a stale s_server from test_single_box.sh"
        echo "is the usual culprit; its trap does not fire if the script is"
        echo "interrupted."
        exit 1
    fi
    gen_cert
    if command -v nginx >/dev/null 2>&1; then
        write_conf
        nginx -c "${CONF}" -p "${DIR}" -t >/dev/null
        nginx -c "${CONF}" -p "${DIR}"
        sleep 1
        echo "origin: nginx on ${ADDR}:${PORT} (pid $(cat "${PIDFILE}" 2>/dev/null))"
    else
        echo "nginx not found -- falling back to openssl s_server."
        echo "WARNING: s_server is single threaded and will cap the measured"
        echo "         rate well below what the proxy can do. Install nginx"
        echo "         before drawing any conclusion: sudo apt install nginx"
        openssl s_server -quiet -accept "${ADDR}:${PORT}" \
            -cert "${DIR}/origin_crt.pem" -key "${DIR}/origin_key.pem" -www \
            >/dev/null 2>&1 &
        echo $! > "${DIR}/origin_sserver_${TAG}.pid"
        sleep 1
        echo "origin: s_server on ${ADDR}:${PORT} (pid $(cat "${DIR}/origin_sserver_${TAG}.pid"))"
    fi
    ;;
stop)
    if [ -f "${PIDFILE}" ]; then
        nginx -c "${CONF}" -p "${DIR}" -s quit 2>/dev/null || \
            kill "$(cat "${PIDFILE}")" 2>/dev/null || true
        rm -f "${PIDFILE}"
    fi
    if [ -f "${DIR}/origin_sserver_${TAG}.pid" ]; then
        kill "$(cat "${DIR}/origin_sserver_${TAG}.pid")" 2>/dev/null || true
        rm -f "${DIR}/origin_sserver_${TAG}.pid"
    fi
    # Anything else still holding the port, however it was started.
    for h in $(port_holders); do
        echo "  killing pid ${h} still on port ${PORT}"
        kill "${h}" 2>/dev/null || true
    done
    sleep 1
    for h in $(port_holders); do
        kill -9 "${h}" 2>/dev/null || true
    done
    if port_in_use; then
        warn_unattributable || true
        echo "origin NOT fully stopped: port ${PORT} is still bound"
        exit 1
    fi
    echo "origin stopped"
    ;;
*)
    echo "usage: $0 {start|stop} [addr] [port]"
    exit 1
    ;;
esac
