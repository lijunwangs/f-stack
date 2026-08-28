/*
 * Platform layer: the same proxy logic runs on F-Stack or on the kernel
 * stack, so the two can be compared with only the transport differing.
 *
 *   make               -> F-Stack (needs DPDK + libfstack)
 *   make STACK=kernel  -> kernel sockets + epoll (needs nothing)
 *
 * Sockets map one to one. The event loop does not -- kqueue and epoll differ
 * enough that emulating one on the other is worse than this three-call
 * abstraction, which is all the proxy actually needs.
 */

#ifndef POC_NET_H
#define POC_NET_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>

#define NET_EV_READ  0x1
#define NET_EV_WRITE 0x2
#define NET_EV_ERR   0x4

#define NET_MAX_EVENTS 512

struct net_event {
    int fd;
    int events;         /* NET_EV_* bitmask */
};

/* Lifecycle. net_run calls loop repeatedly until it returns non-zero. */
int net_init(int argc, char *argv[]);
void net_run(int (*loop)(void *), void *arg);
const char *net_stack_name(void);

/* Sockets. Semantics and errno follow the POSIX calls of the same name. */
int net_socket(int domain, int type, int protocol);
int net_bind(int fd, const struct sockaddr *addr, socklen_t len);
int net_listen(int fd, int backlog);
int net_accept(int fd);
int net_connect(int fd, const struct sockaddr *addr, socklen_t len);
int net_close(int fd);
ssize_t net_read(int fd, void *buf, size_t len);
ssize_t net_write(int fd, const void *buf, size_t len);
int net_setsockopt(int fd, int level, int name, const void *val, socklen_t len);
int net_getsockopt(int fd, int level, int name, void *val, socklen_t *len);
int net_set_nonblock(int fd);

/* Event loop. ev_watch(add=0) removes the interest. */
int ev_create(void);
int ev_watch(int ev, int fd, int events, int add);
/*
 * Set an fd's interest to exactly `events`, adding and removing filters as
 * needed. ev_watch cannot express this portably: kqueue tracks one filter per
 * call, while epoll replaces the whole mask and treats add=0 as "forget the
 * fd". Arming write interest without losing read interest needs this.
 */
int ev_set(int ev, int fd, int events);
int ev_wait(int ev, struct net_event *out, int max);

#endif /* POC_NET_H */
