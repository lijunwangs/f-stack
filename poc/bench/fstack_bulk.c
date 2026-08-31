/*
 * Minimal F-Stack bulk sender, to answer one question: can this stack push
 * bytes at speed with nothing else in the way?
 *
 * The proxy wedges under load -- a write that returns EAGAIN forever while
 * the peer's window is open and the wire is idle. That could be the proxy's
 * relay logic or the stack underneath it, and no amount of staring at the
 * proxy separates the two. So this strips everything the proxy does: no TLS,
 * no scanning, no second leg, no certificate. Accept a connection, answer any
 * request with a large fixed body, and keep a single offset per connection.
 *
 * If this wedges too, the fault is under the socket API and the proxy is
 * exonerated. If it runs clean at speed, the fault is ours and this is the
 * throughput the proxy should be reaching.
 *
 * Build with the flags the bundled example uses (see poc/README.md).
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "ff_api.h"
#include "ff_config.h"

#define MAX_EVENTS   512
#define MAX_FD       65536
#define BODY_BYTES   (1024 * 1024)
#define HDR_MAX      256

static int kq;
static int listen_fd = -1;
static char *response;          /* header + body, sent verbatim */
static size_t response_len;

/* Per connection: how much of the response has gone out. */
static size_t sent[MAX_FD];
static int active[MAX_FD];

static unsigned long total_bytes, total_responses, total_eagain;
static time_t last_report;

static void build_response(void)
{
    int hdr;

    response = malloc(HDR_MAX + BODY_BYTES);
    if (!response) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    hdr = snprintf(response, HDR_MAX,
                   "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/octet-stream\r\n"
                   "Content-Length: %d\r\n"
                   "Connection: keep-alive\r\n"
                   "\r\n", BODY_BYTES);
    memset(response + hdr, 'x', BODY_BYTES);
    response_len = (size_t)hdr + BODY_BYTES;
}

static void watch(int fd, int filter, int add)
{
    struct kevent kev;

    EV_SET(&kev, fd, filter, add ? (EV_ADD | EV_CLEAR) : EV_DELETE, 0, 0, NULL);
    ff_kevent(kq, &kev, 1, NULL, 0, NULL);
}

static void drop(int fd)
{
    active[fd] = 0;
    sent[fd] = response_len;
    ff_close(fd);
}

/*
 * Push what is left of the response. Stops on a short write and asks to be
 * told when the socket drains, which is the exact pattern the proxy uses and
 * the exact pattern suspected of never being resumed.
 */
static void push(int fd)
{
    while (sent[fd] < response_len) {
        ssize_t w = ff_write(fd, response + sent[fd], response_len - sent[fd]);

        if (w > 0) {
            sent[fd] += (size_t)w;
            total_bytes += (unsigned long)w;
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                      errno == ENOBUFS)) {
            total_eagain++;
            watch(fd, EVFILT_WRITE, 1);
            return;
        }
        drop(fd);
        return;
    }
    /* Response complete: stop asking about writability, await the next request. */
    watch(fd, EVFILT_WRITE, 0);
    total_responses++;
}

/*
 * Retry every connection that still owes bytes, without waiting to be told
 * the socket drained. This separates the two possible faults: if the writes
 * start succeeding, write readiness simply was not being reported and polling
 * is a workaround; if they keep returning EAGAIN, the send buffer genuinely
 * never drains and the stack is not transmitting at all.
 */
static int poll_stalled;

static void retry_stalled(void)
{
    int fd;

    if (!poll_stalled)
        return;
    for (fd = 0; fd < MAX_FD; fd++)
        if (active[fd] && sent[fd] < response_len)
            push(fd);
}

static int loop(void *arg)
{
    struct kevent events[MAX_EVENTS];
    int n, i;
    time_t now;

    retry_stalled();
    n = ff_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    for (i = 0; i < n; i++) {
        int fd = (int)events[i].ident;

        if (fd == listen_fd) {
            for (;;) {
                int c = ff_accept(listen_fd, NULL, NULL);

                if (c < 0 || c >= MAX_FD)
                    break;
                active[c] = 1;
                sent[c] = response_len;   /* nothing owed until asked */
                watch(c, EVFILT_READ, 1);
            }
            continue;
        }
        if (fd < 0 || fd >= MAX_FD || !active[fd])
            continue;

        if (events[i].flags & EV_EOF) {
            drop(fd);
            continue;
        }
        if (events[i].filter == EVFILT_READ) {
            char buf[2048];
            ssize_t r = ff_read(fd, buf, sizeof(buf));

            if (r == 0) {
                drop(fd);
                continue;
            }
            if (r > 0 && sent[fd] >= response_len) {
                sent[fd] = 0;             /* start a fresh response */
                push(fd);
            }
            continue;
        }
        if (events[i].filter == EVFILT_WRITE)
            push(fd);
    }

    now = time(NULL);
    if (now - last_report >= 2) {
        double dt = (double)(now - last_report);

        printf("[bulk] %.1f MB/s responses=%lu eagain=%lu\n",
               total_bytes / dt / 1e6, total_responses, total_eagain);
        fflush(stdout);
        total_bytes = 0;
        last_report = now;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    struct sockaddr_in addr;
    int on = 1;

    build_response();
    poll_stalled = getenv("BULK_POLL") != NULL;
    if (ff_init(argc, argv) != 0) {
        fprintf(stderr, "ff_init failed\n");
        return 1;
    }

    listen_fd = ff_socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        fprintf(stderr, "ff_socket failed\n");
        return 1;
    }
    ff_setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    ff_ioctl(listen_fd, FIONBIO, &on);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(8080);
    if (ff_bind(listen_fd, (struct linux_sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "ff_bind failed\n");
        return 1;
    }
    if (ff_listen(listen_fd, 4096) < 0) {
        fprintf(stderr, "ff_listen failed\n");
        return 1;
    }

    kq = ff_kqueue();
    watch(listen_fd, EVFILT_READ, 1);
    last_report = time(NULL);

    printf("[bulk] serving %d-byte bodies on 8080, poll_stalled=%d\n",
           BODY_BYTES, poll_stalled);
    fflush(stdout);
    ff_run(loop, NULL);
    return 0;
}
