/* Platform layer over F-Stack: ff_* sockets and kqueue. */

#include <sys/ioctl.h>

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
    if (events & NET_EV_READ) {
        EV_SET(&ch, fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
        if (ff_kevent(ev, &ch, 1, NULL, 0, NULL) < 0)
            return -1;
    }
    if (events & NET_EV_WRITE) {
        EV_SET(&ch, fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, NULL);
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

int ev_wait(int ev, struct net_event *out, int max)
{
    struct kevent evs[NET_MAX_EVENTS];
    int n, i;

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
