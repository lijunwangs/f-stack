/*
 * POC entry point: one lcore, one listen socket, kqueue event loop.
 *
 * Configuration comes from the environment so that argv stays free for
 * the stack layer (F-Stack and DPDK consume argv; the kernel build ignores it):
 *   POC_LISTEN_PORT  port to listen on            (default 8443)
 *   POC_ORIGIN       upstream as ip:port          (required)
 *   POC_PATTERN      literal the scan looks for   (default "SECRET-CANARY")
 *   POC_CA_OUT       write the POC CA here as PEM (default poc_ca.pem)
 *   POC_STATS_SEC    stats interval in seconds    (default 5)
 *   POC_RELAY_BUDGET bytes one leg moves per visit  (default 262144)
 *   POC_LOOP_BUDGET  bytes the loop moves per pass  (default 262144)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "net.h"
#include "prof.h"
#include "session.h"

#define MAX_EVENTS NET_MAX_EVENTS

uint64_t prof_cyc[P_N];
uint64_t prof_cnt[P_N];
const char *prof_name[P_N] = {
    "evwait", "evset", "sockrd", "sockwr",
    "sslrd", "sslwr", "scan", "hshake"
};
uint64_t prof_events;
uint64_t prof_rd_calls, prof_rd_bytes, prof_rd_done;
uint64_t prof_queued, prof_queued_n;
uint64_t prof_relay_calls;
uint64_t prof_relay_bytes;
static uint64_t prof_mark;

void prof_report(char *out, size_t len, uint64_t interval_cycles)
{
    size_t used = 0;
    int i;

    if (interval_cycles == 0)
        return;
    for (i = 0; i < P_N && used + 24 < len; i++) {
        double pct = 100.0 * (double)prof_cyc[i] / (double)interval_cycles;

        used += (size_t)snprintf(out + used, len - used, " %s=%.1f%%/%lu",
                                 prof_name[i], pct,
                                 (unsigned long)prof_cnt[i]);
        prof_cyc[i] = 0;
        prof_cnt[i] = 0;
    }
}

static int listen_fd = -1;
static int kq = -1;
static struct sockaddr_in origin_addr;
static struct net_event events[MAX_EVENTS];
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

    char wire[256];

    forge_stats(&hits, &mints);
    scan_stats(&sbytes, &shits);
    net_stack_stats(wire, sizeof(wire));
    printf("[poc] sessions=%lu ohs=%lu chs=%lu done=%lu failed=%lu blocked=%lu "
           "rx=%luKB tx=%luKB certs=%lu/%lu scanned=%luKB matches=%lu "
           "txblock=%lu txnobufs=%lu%s\n",
           s->sessions, s->origin_handshakes, s->client_handshakes,
           s->completed, s->failed, s->blocked,
           s->rx_bytes / 1024, s->tx_bytes / 1024,
           mints, hits, sbytes / 1024, shits, s->tx_block, s->tx_nobufs,
           wire);
    {
        char prof[512];
        uint64_t now = prof_tsc();

        unsigned long prof_wait_calls = (unsigned long)prof_cnt[P_EVWAIT];

        prof[0] = '\0';
        prof_report(prof, sizeof(prof), now - prof_mark);
        prof_mark = now;
        if (prof[0])
            printf("[poc] cpu:%s\n", prof);
        printf("[poc] loop: waits=%lu events=%lu ev_per_wait=%.2f "
               "relay_calls=%lu relay_MB=%.1f MB_per_relay=%.1fKB\n",
               (unsigned long)prof_wait_calls,
               (unsigned long)prof_events,
               prof_wait_calls ? (double)prof_events / prof_wait_calls : 0.0,
               (unsigned long)prof_relay_calls,
               prof_relay_bytes / 1e6,
               prof_relay_calls ?
                   prof_relay_bytes / prof_relay_calls / 1024.0 : 0.0);
        printf("[poc] reads: n=%lu avg_got=%.0fB avg_queued_before=%.0fB\n",
               (unsigned long)prof_rd_done,
               prof_rd_done ? (double)prof_rd_bytes / prof_rd_done : 0.0,
               prof_queued_n ? (double)prof_queued / prof_queued_n : 0.0);
        prof_events = 0;
        prof_relay_calls = 0;
        prof_relay_bytes = 0;
        prof_rd_bytes = 0;
        prof_rd_done = 0;
        prof_queued = 0;
        prof_queued_n = 0;
    }
    fflush(stdout);
    session_report_stalled();
}

static int loop(void *arg)
{
    int n, i;
    time_t now;

    /* Don't wait on the network when a transfer is mid-flight and already
     * owed another turn; just collect whatever is ready and get back to it. */
    loop_moved = 0;         /* the stack gets the thread back within a budget */
    PROF_V(P_EVWAIT, n, ev_wait(kq, events, MAX_EVENTS,
                                session_pending() ? 0 : 1000));
    if (n > 0)
        prof_events += (uint64_t)n;
    if (n < 0) {
        fprintf(stderr, "[poc] ev_wait: %s\n", strerror(errno));
        return -1;
    }

    for (i = 0; i < n; i++) {
        int fd = events[i].fd;

        if (events[i].events & NET_EV_ERR) {
            struct session *s = session_lookup(fd);

            if (s)
                session_close(s);
            continue;
        }

        if (fd == listen_fd) {
            for (;;) {
                int cfd = net_accept(listen_fd);

                if (cfd < 0)
                    break;
                if (!session_new(kq, cfd, &origin_addr))
                    net_close(cfd);
            }
            continue;
        }

        {
            struct session *s = session_lookup(fd);

            if (s)
                session_event(s, fd, events[i].events);
        }
    }

    /* Transfers that hit their work budget get their next turn here, after
     * the stack has had the thread back. */
    session_run_pending();

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
    int on = 1;

    listen_fd = net_socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        fprintf(stderr, "[poc] net_socket: %s\n", strerror(errno));
        return -1;
    }
    net_setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    net_set_nonblock(listen_fd);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (net_bind(listen_fd, (const struct sockaddr *)&addr,
                 sizeof(addr)) < 0) {
        fprintf(stderr, "[poc] net_bind(%d): %s\n", port, strerror(errno));
        return -1;
    }
    if (net_listen(listen_fd, 4096) < 0) {
        fprintf(stderr, "[poc] net_listen: %s\n", strerror(errno));
        return -1;
    }

    kq = ev_create();
    if (kq < 0) {
        fprintf(stderr, "[poc] ev_create: %s\n", strerror(errno));
        return -1;
    }
    if (ev_watch(kq, listen_fd, NET_EV_READ, 1) < 0) {
        fprintf(stderr, "[poc] ev_watch listener: %s\n", strerror(errno));
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
    /*
     * How much one leg may move before handing the thread back. Tunable
     * because the port drops packets when the stack waits too long for it,
     * and where that line falls is what we are measuring.
     */
    relay_budget = (size_t)env_int("POC_RELAY_BUDGET", RELAY_BUDGET_DEFAULT);
    loop_budget = (size_t)env_int("POC_LOOP_BUDGET", LOOP_BUDGET_DEFAULT);
    rx_batch_min = (size_t)env_int("POC_RX_BATCH", RX_BATCH_MIN_DEFAULT);
    rx_batch_wait_us = env_int("POC_RX_WAIT_US", RX_BATCH_WAIT_US_DEF);

    /*
     * A proxy writes into sockets the peer may have just closed, which is
     * routine under connection churn. On the kernel stack that raises
     * SIGPIPE and the default action kills the process -- silently, with no
     * log line and no core. EPIPE from write() is what we want instead.
     * F-Stack never signals the process, so only the kernel build is
     * affected, which is how this went unnoticed.
     */
    signal(SIGPIPE, SIG_IGN);

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

    if (net_init(argc, argv) != 0) {
        fprintf(stderr, "net_init failed\n");
        return 1;
    }
    if (setup_listener(port) != 0)
        return 1;

    printf("[poc] stack=%s listening on %d, origin %s, CA at %s\n",
           net_stack_name(), port, origin,
           ca_out && *ca_out ? ca_out : "poc_ca.pem");
    fflush(stdout);
    last_stats = time(NULL);
    prof_mark = prof_tsc();

    net_run(loop, NULL);
    forge_fini();
    return 0;
}
