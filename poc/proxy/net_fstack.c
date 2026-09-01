/* Platform layer over F-Stack: ff_* sockets and kqueue. */

#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <stdlib.h>
#include <string.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>

#include "ff_api.h"
#include "ff_config.h"
#include "net.h"

const char *net_stack_name(void) { return "f-stack"; }

int net_init(int argc, char *argv[]) { return ff_init(argc, argv); }

void net_run(int (*loop)(void *), void *arg) { ff_run(loop, arg); }

int net_socket(int domain, int type, int protocol)
{
    return ff_socket(domain, type, protocol);
}

int net_bind(int fd, const struct sockaddr *addr, socklen_t len)
{
    return ff_bind(fd, (const struct linux_sockaddr *)addr, len);
}

int net_listen(int fd, int backlog) { return ff_listen(fd, backlog); }

int net_accept(int fd) { return ff_accept(fd, NULL, NULL); }

int net_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    return ff_connect(fd, (const struct linux_sockaddr *)addr, len);
}

int net_close(int fd) { return ff_close(fd); }

ssize_t net_read(int fd, void *buf, size_t len) { return ff_read(fd, buf, len); }

ssize_t net_write(int fd, const void *buf, size_t len)
{
    return ff_write(fd, buf, len);
}

int net_setsockopt(int fd, int level, int name, const void *val, socklen_t len)
{
    return ff_setsockopt(fd, level, name, val, len);
}

int net_getsockopt(int fd, int level, int name, void *val, socklen_t *len)
{
    return ff_getsockopt(fd, level, name, val, len);
}

int net_set_nonblock(int fd)
{
    int on = 1;

    return ff_ioctl(fd, FIONBIO, &on);
}

int ev_create(void) { return ff_kqueue(); }

int ev_set(int ev, int fd, int events)
{
    struct kevent ch;

    /*
     * Deletes go first and their result is ignored: EV_DELETE of a filter
     * that was never added returns ENOENT, which is the normal case here.
     * One kevent call per change, because with an empty eventlist a failing
     * change aborts the rest of the batch.
     */
    if (!(events & NET_EV_READ)) {
        EV_SET(&ch, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        ff_kevent(ev, &ch, 1, NULL, 0, NULL);
    }
    if (!(events & NET_EV_WRITE)) {
        EV_SET(&ch, fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        ff_kevent(ev, &ch, 1, NULL, 0, NULL);
    }
    /*
     * Level-triggered on purpose: no EV_CLEAR. The relay hands control back
     * to the stack before a large transfer is finished, so readiness has to
     * be re-reported rather than announced once.
     */
    if (events & NET_EV_READ) {
        EV_SET(&ch, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
        if (ff_kevent(ev, &ch, 1, NULL, 0, NULL) < 0)
            return -1;
    }
    if (events & NET_EV_WRITE) {
        EV_SET(&ch, fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
        if (ff_kevent(ev, &ch, 1, NULL, 0, NULL) < 0)
            return -1;
    }
    return 0;
}

int ev_watch(int ev, int fd, int events, int add)
{
    struct kevent ch[2];
    int n = 0;
    unsigned short flags = add ? (EV_ADD | EV_CLEAR) : EV_DELETE;

    if (events & NET_EV_READ)
        EV_SET(&ch[n++], fd, EVFILT_READ, flags, 0, 0, NULL);
    if (events & NET_EV_WRITE)
        EV_SET(&ch[n++], fd, EVFILT_WRITE, flags, 0, 0, NULL);
    if (n == 0)
        return 0;
    return ff_kevent(ev, ch, n, NULL, 0, NULL);
}

int ev_wait(int ev, struct net_event *out, int max, int timeout_ms)
{
    struct kevent evs[NET_MAX_EVENTS];
    int n, i;

    (void)timeout_ms;   /* this stack polls; it never waits for an event */
    if (max > NET_MAX_EVENTS)
        max = NET_MAX_EVENTS;
    n = ff_kevent(ev, NULL, 0, evs, max, NULL);
    if (n < 0)
        return n;

    for (i = 0; i < n; i++) {
        out[i].fd = (int)evs[i].ident;
        out[i].events = 0;
        if (evs[i].filter == EVFILT_READ)
            out[i].events |= NET_EV_READ;
        if (evs[i].filter == EVFILT_WRITE)
            out[i].events |= NET_EV_WRITE;
        if (evs[i].flags & EV_ERROR)
            out[i].events |= NET_EV_ERR;
    }
    return n;
}

/*
 * Port and buffer counters, straight from DPDK. imissed is the one that
 * matters most: it counts packets the port had nowhere to put, which is
 * invisible to the sockets above and looks like a slow peer from up there.
 * A falling free-buffer count over a run means the pool is leaking, which
 * starves the receive refill and stops the port dead.
 *
 * Port 0 and mbuf_pool_0 match a single-port, single-socket config; a wider
 * deployment would walk the port list.
 */
/*
 * Dump every non-zero extended counter, plus queue and link state. Called once
 * when the port stops receiving: that failure has been seen twice, with
 * ipkts and opkts frozen, no ierrors, no oerrors, an untouched mbuf pool and
 * the link still reported up, recovering only on a process restart. Nothing in
 * the ordinary counters distinguishes it from an idle link, so when it happens
 * we want everything the driver is willing to say, once.
 */
static void dump_port_state(void)
{
    struct rte_eth_xstat_name *names = NULL;
    struct rte_eth_xstat *vals = NULL;
    struct rte_eth_dev_info info;
    struct rte_eth_link link;
    int n, i;

    memset(&info, 0, sizeof(info));
    memset(&link, 0, sizeof(link));
    rte_eth_dev_info_get(0, &info);
    rte_eth_link_get_nowait(0, &link);
    fprintf(stderr, "[poc] PORT STALLED: link=%d speed=%u rxq=%u txq=%u "
            "driver=%s\n", link.link_status, link.link_speed,
            info.nb_rx_queues, info.nb_tx_queues,
            info.driver_name ? info.driver_name : "?");

    n = rte_eth_xstats_get_names(0, NULL, 0);
    if (n <= 0)
        return;
    names = calloc((size_t)n, sizeof(*names));
    vals = calloc((size_t)n, sizeof(*vals));
    if (!names || !vals)
        goto done;
    if (rte_eth_xstats_get_names(0, names, (unsigned)n) != n ||
        rte_eth_xstats_get(0, vals, (unsigned)n) != n)
        goto done;
    for (i = 0; i < n; i++)
        if (vals[i].value != 0)
            fprintf(stderr, "[poc]   xstat %s=%llu\n", names[i].name,
                    (unsigned long long)vals[i].value);
done:
    free(names);
    free(vals);
}

/*
 * Any non-zero extended counter whose name suggests a discard. The basic
 * stats show imissed and ierrors only; a port that accepts a TSO request and
 * then fails to segment it reports that here or nowhere.
 */
static void append_xstats(char *out, size_t len)
{
    struct rte_eth_xstat_name *names = NULL;
    struct rte_eth_xstat *vals = NULL;
    size_t used = strlen(out);
    int n, i;

    n = rte_eth_xstats_get_names(0, NULL, 0);
    if (n <= 0)
        return;
    names = calloc((size_t)n, sizeof(*names));
    vals = calloc((size_t)n, sizeof(*vals));
    if (!names || !vals)
        goto done;
    if (rte_eth_xstats_get_names(0, names, (unsigned)n) != n ||
        rte_eth_xstats_get(0, vals, (unsigned)n) != n)
        goto done;

    for (i = 0; i < n && used + 40 < len; i++) {
        if (vals[i].value == 0)
            continue;
        if (!strstr(names[i].name, "drop") &&
            !strstr(names[i].name, "error") &&
            !strstr(names[i].name, "discard") &&
            !strstr(names[i].name, "tso") &&
            !strstr(names[i].name, "TSO"))
            continue;
        used += (size_t)snprintf(out + used, len - used, " %s=%llu",
                                 names[i].name,
                                 (unsigned long long)vals[i].value);
    }
done:
    free(names);
    free(vals);
}

void net_stack_stats(char *out, size_t len)
{
    struct rte_eth_stats st;
    struct rte_mempool *mp;
    unsigned avail = 0, used = 0;
    double skew = 0.0;
    int up = -1;
    unsigned speed = 0;

    if (rte_eth_stats_get(0, &st) != 0) {
        snprintf(out, len, "");
        return;
    }
    mp = rte_mempool_lookup("mbuf_pool_0");
    if (mp) {
        avail = rte_mempool_avail_count(mp);
        used = rte_mempool_in_use_count(mp);
    }
    /*
     * The stack's own clock, next to the host's. TCP output stalls when the
     * send buffer is full, because sosend returns EWOULDBLOCK without calling
     * tcp_output: only an incoming ACK or a timer can restart it. If this
     * clock is not advancing then no timer will ever fire, and a connection
     * that stops has no way back. Comparing the two says which.
     */
    {
        struct timeval ftv;
        struct timespec hts;

        ff_gettimeofday(&ftv, NULL);
        clock_gettime(CLOCK_REALTIME, &hts);
        skew = (double)ftv.tv_sec + ftv.tv_usec / 1e6
             - ((double)hts.tv_sec + hts.tv_nsec / 1e9);
    }

    {
        struct rte_eth_link link;

        memset(&link, 0, sizeof(link));
        rte_eth_link_get_nowait(0, &link);
        up = link.link_status ? 1 : 0;
        speed = link.link_speed;
    }

    snprintf(out, len,
             " | link=%s/%uMbps"
             " | stackclock=%+.3fs vs host"
             " | port ipkts=%llu opkts=%llu imissed=%llu ierr=%llu oerr=%llu "
             "rxnombuf=%llu mbuf=%u/%u",
             up > 0 ? "up" : (up == 0 ? "DOWN" : "?"), speed,
             skew,
             (unsigned long long)st.ipackets, (unsigned long long)st.opackets,
             (unsigned long long)st.imissed, (unsigned long long)st.ierrors,
             (unsigned long long)st.oerrors, (unsigned long long)st.rx_nombuf,
             avail, avail + used);
    append_xstats(out, len);

    /*
     * Watch for the port going deaf. Three consecutive intervals with no
     * received packet at all, while the process is clearly meant to be
     * serving, is the signature; dump once so the log holds the evidence.
     */
    {
        static unsigned long long last_ipkts;
        static int quiet;
        static int dumped;

        if (st.ipackets == last_ipkts) {
            quiet++;
            if (quiet == 3 && !dumped) {
                dumped = 1;
                dump_port_state();
            }
            /*
             * Keep saying so, every interval, for as long as it lasts. The
             * cause of this is not known and could not be reproduced, so the
             * practical defence is that it must be impossible to miss and
             * trivially detectable by a supervisor: the one thing known to
             * cure it is restarting the process.
             */
            if (quiet >= 3)
                fprintf(stderr, "[poc] PORT DEAF for %d intervals -- no "
                        "packet received; restart is the only known "
                        "recovery\n", quiet);
        } else {
            if (quiet >= 3)
                fprintf(stderr, "[poc] port receiving again after %d "
                        "intervals\n", quiet);
            last_ipkts = st.ipackets;
            quiet = 0;
            dumped = 0;
        }
    }
}

int net_pending(int fd)
{
    int n = 0;

    if (ff_ioctl(fd, FIONREAD, &n) < 0)
        return -1;
    return n;
}
