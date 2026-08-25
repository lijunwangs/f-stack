/* Platform layer over the kernel stack: POSIX sockets and epoll.
 * Needs no DPDK, so this build runs anywhere and is the control for any
 * comparison against a stock proxy. */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <sys/epoll.h>

#include "net.h"

const char *net_stack_name(void) { return "kernel"; }

int net_init(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    return 0;
}

void net_run(int (*loop)(void *), void *arg)
{
    while (loop(arg) == 0)
        ;
}

int net_socket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

int net_bind(int fd, const struct sockaddr *addr, socklen_t len)
{
    return bind(fd, addr, len);
}

int net_listen(int fd, int backlog) { return listen(fd, backlog); }

int net_accept(int fd) { return accept(fd, NULL, NULL); }

int net_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    return connect(fd, addr, len);
}

int net_close(int fd) { return close(fd); }

ssize_t net_read(int fd, void *buf, size_t len) { return read(fd, buf, len); }

ssize_t net_write(int fd, const void *buf, size_t len)
{
    return write(fd, buf, len);
}

int net_setsockopt(int fd, int level, int name, const void *val, socklen_t len)
{
    return setsockopt(fd, level, name, val, len);
}

int net_getsockopt(int fd, int level, int name, void *val, socklen_t *len)
{
    return getsockopt(fd, level, name, val, len);
}

int net_set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);

    if (fl < 0)
        return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

int ev_create(void) { return epoll_create1(0); }

/*
 * Edge triggered, to match the EV_CLEAR the kqueue path uses. epoll has one
 * registration per fd rather than one per direction, so a watch has to carry
 * the whole desired mask and ADD or MOD as appropriate.
 */
int ev_watch(int ev, int fd, int events, int add)
{
    struct epoll_event e;

    memset(&e, 0, sizeof(e));
    e.data.fd = fd;
    if (events & NET_EV_READ)
        e.events |= EPOLLIN;
    if (events & NET_EV_WRITE)
        e.events |= EPOLLOUT;
    e.events |= EPOLLET;

    if (!add)
        return epoll_ctl(ev, EPOLL_CTL_DEL, fd, &e);
    if (epoll_ctl(ev, EPOLL_CTL_ADD, fd, &e) == 0)
        return 0;
    if (errno != EEXIST)
        return -1;
    return epoll_ctl(ev, EPOLL_CTL_MOD, fd, &e);
}

int ev_wait(int ev, struct net_event *out, int max)
{
    struct epoll_event evs[NET_MAX_EVENTS];
    int n, i;

    if (max > NET_MAX_EVENTS)
        max = NET_MAX_EVENTS;
    n = epoll_wait(ev, evs, max, 1000);
    if (n < 0)
        return errno == EINTR ? 0 : -1;

    for (i = 0; i < n; i++) {
        out[i].fd = evs[i].data.fd;
        out[i].events = 0;
        if (evs[i].events & EPOLLIN)
            out[i].events |= NET_EV_READ;
        if (evs[i].events & EPOLLOUT)
            out[i].events |= NET_EV_WRITE;
        if (evs[i].events & (EPOLLERR | EPOLLHUP))
            out[i].events |= NET_EV_ERR;
    }
    return n;
}
