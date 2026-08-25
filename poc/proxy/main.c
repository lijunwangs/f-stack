/*
 * POC entry point: one lcore, one listen socket, kqueue event loop.
 *
 * Configuration comes from the environment so that argv stays free for
 * F-Stack and DPDK:
 *   POC_LISTEN_PORT  port to listen on            (default 8443)
 *   POC_ORIGIN       upstream as ip:port          (required)
 *   POC_PATTERN      literal the scan looks for   (default "SECRET-CANARY")
 *   POC_CA_OUT       write the POC CA here as PEM (default poc_ca.pem)
 *   POC_STATS_SEC    stats interval in seconds    (default 5)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "ff_api.h"
#include "ff_config.h"
#include "session.h"

#define MAX_EVENTS 512

static int listen_fd = -1;
static int kq = -1;
static struct sockaddr_in origin_addr;
static struct kevent events[MAX_EVENTS];
static time_t last_stats;
static long stats_interval = 5;

static int env_int(const char *name, int dflt)
{
    const char *v = getenv(name);

    return v && *v ? atoi(v) : dflt;
}

static int parse_origin(const char *spec, struct sockaddr_in *out)
{
    char host[64];
    const char *colon = strrchr(spec, ':');
    size_t hlen;

    if (!colon)
        return -1;
    hlen = (size_t)(colon - spec);
    if (hlen == 0 || hlen >= sizeof(host))
        return -1;
    memcpy(host, spec, hlen);
    host[hlen] = '\0';

    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons((uint16_t)atoi(colon + 1));
    if (inet_pton(AF_INET, host, &out->sin_addr) != 1)
        return -1;
    return 0;
}

static void print_stats(void)
{
    struct poc_stats *s = session_stats();
    unsigned long hits = 0, mints = 0, sbytes = 0, shits = 0;

    forge_stats(&hits, &mints);
    scan_stats(&sbytes, &shits);
    printf("[poc] sessions=%lu ohs=%lu chs=%lu done=%lu failed=%lu blocked=%lu "
           "rx=%luKB tx=%luKB certs=%lu/%lu scanned=%luKB matches=%lu\n",
           s->sessions, s->origin_handshakes, s->client_handshakes,
           s->completed, s->failed, s->blocked,
           s->rx_bytes / 1024, s->tx_bytes / 1024,
           mints, hits, sbytes / 1024, shits);
    fflush(stdout);
}

static int loop(void *arg)
{
    int n, i;
    time_t now;

    n = ff_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    if (n < 0) {
        fprintf(stderr, "[poc] ff_kevent: %s\n", strerror(errno));
        return -1;
    }

    for (i = 0; i < n; i++) {
        int fd = (int)events[i].ident;

        if (events[i].flags & EV_ERROR) {
            struct session *s = session_lookup(fd);

            if (s)
                session_close(s);
            continue;
        }

        if (fd == listen_fd) {
            for (;;) {
                int cfd = ff_accept(listen_fd, NULL, NULL);

                if (cfd < 0)
                    break;
                if (!session_new(kq, cfd, &origin_addr))
                    ff_close(cfd);
            }
            continue;
        }

        {
            struct session *s = session_lookup(fd);

            if (s)
                session_event(s, fd, (int)events[i].filter);
        }
    }

    now = time(NULL);
    if (stats_interval > 0 && now - last_stats >= stats_interval) {
        last_stats = now;
        print_stats();
    }
    return 0;
}

static int setup_listener(int port)
{
    struct sockaddr_in addr;
    struct kevent ev;
    int on = 1;

    listen_fd = ff_socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        fprintf(stderr, "[poc] ff_socket: %s\n", strerror(errno));
        return -1;
    }
    ff_setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    ff_ioctl(listen_fd, FIONBIO, &on);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (ff_bind(listen_fd, (const struct linux_sockaddr *)&addr,
                sizeof(addr)) < 0) {
        fprintf(stderr, "[poc] ff_bind(%d): %s\n", port, strerror(errno));
        return -1;
    }
    if (ff_listen(listen_fd, 4096) < 0) {
        fprintf(stderr, "[poc] ff_listen: %s\n", strerror(errno));
        return -1;
    }

    kq = ff_kqueue();
    if (kq < 0) {
        fprintf(stderr, "[poc] ff_kqueue: %s\n", strerror(errno));
        return -1;
    }
    EV_SET(&ev, listen_fd, EVFILT_READ, EV_ADD, 0, MAX_EVENTS, NULL);
    if (ff_kevent(kq, &ev, 1, NULL, 0, NULL) < 0) {
        fprintf(stderr, "[poc] ff_kevent add listener: %s\n",
                strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    const char *origin = getenv("POC_ORIGIN");
    const char *pattern = getenv("POC_PATTERN");
    const char *ca_out = getenv("POC_CA_OUT");
    int port;

    if (!origin) {
        fprintf(stderr, "POC_ORIGIN is required, as ip:port\n");
        return 1;
    }
    if (parse_origin(origin, &origin_addr) != 0) {
        fprintf(stderr, "cannot parse POC_ORIGIN '%s'\n", origin);
        return 1;
    }
    port = env_int("POC_LISTEN_PORT", 8443);
    stats_interval = env_int("POC_STATS_SEC", 5);

    if (scan_init(pattern && *pattern ? pattern : "SECRET-CANARY") != 0) {
        fprintf(stderr, "scan_init failed\n");
        return 1;
    }
    if (forge_init() != 0) {
        fprintf(stderr, "forge_init failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (forge_export_ca(ca_out && *ca_out ? ca_out : "poc_ca.pem") != 0)
        fprintf(stderr, "[poc] warning: could not write the CA PEM\n");

    if (ff_init(argc, argv) != 0) {
        fprintf(stderr, "ff_init failed\n");
        return 1;
    }
    if (setup_listener(port) != 0)
        return 1;

    printf("[poc] listening on %d, origin %s, CA at %s\n", port, origin,
           ca_out && *ca_out ? ca_out : "poc_ca.pem");
    fflush(stdout);
    last_stats = time(NULL);

    ff_run(loop, NULL);
    forge_fini();
    return 0;
}
