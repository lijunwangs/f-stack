/* Platform layer over F-Stack: ff_* sockets and kqueue. */

#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/time.h>

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
void net_stack_stats(char *out, size_t len)
{
    struct rte_eth_stats st;
    struct rte_mempool *mp;
    unsigned avail = 0, used = 0;
    double skew = 0.0;

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

    snprintf(out, len,
             " | stackclock=%+.3fs vs host"
             " | port ipkts=%llu opkts=%llu imissed=%llu ierr=%llu oerr=%llu "
             "rxnombuf=%llu mbuf=%u/%u",
             skew,
             (unsigned long long)st.ipackets, (unsigned long long)st.opackets,
             (unsigned long long)st.imissed, (unsigned long long)st.ierrors,
             (unsigned long long)st.oerrors, (unsigned long long)st.rx_nombuf,
             avail, avail + used);
}
