/*
 * Session state machine: origin-first TLS interception on one lcore.
 *
 * Both legs are driven from the event loop through memory BIOs, so every
 * socket call is ours and the buffered ClientHello can be replayed into the
 * client-leg SSL object. Replacing these with BIOs backed by mbuf memory is
 * M2 work and needs a write-side segment accessor in the lib; see the copy
 * budget section of the design doc.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "ff_api.h"
#include "session.h"

#include "proxy.h"

enum {
    ST_CH = 0,      /* buffering the ClientHello */
    ST_OCONNECT,    /* origin TCP connect in flight */
    ST_OHS,         /* origin TLS handshake */
    ST_CHS,         /* client TLS handshake, forged leaf */
    ST_RELAY,
    ST_DEAD
};

static const char *st_name[] = { "CH", "OCONNECT", "OHS", "CHS", "RELAY",
                                 "DEAD" };

static struct session *by_fd[POC_MAX_FD];
static struct poc_stats stats;

struct poc_stats *session_stats(void) { return &stats; }

static void set_nonblock(int fd)
{
    int on = 1;

    ff_ioctl(fd, FIONBIO, &on);
}

static int kq_watch(int kq, int fd, int filter, int add)
{
    struct kevent ev;

    EV_SET(&ev, fd, filter, add ? (EV_ADD | EV_CLEAR) : EV_DELETE, 0, 0, NULL);
    return ff_kevent(kq, &ev, 1, NULL, 0, NULL);
}

/* ---- lifecycle -------------------------------------------------------- */

struct session *session_new(int kq, int cfd, const struct sockaddr_in *origin)
{
    struct session *s;

    if (cfd < 0 || cfd >= POC_MAX_FD)
        return NULL;

    s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;

    s->kq = kq;
    s->cfd = cfd;
    s->ofd = -1;
    s->state = ST_CH;
    s->origin = *origin;

    set_nonblock(cfd);
    by_fd[cfd] = s;
    if (kq_watch(kq, cfd, EVFILT_READ, 1) < 0) {
        session_close(s);
        return NULL;
    }
    stats.sessions++;
    return s;
}

struct session *session_lookup(int fd)
{
    if (fd < 0 || fd >= POC_MAX_FD)
        return NULL;
    return by_fd[fd];
}

void session_close(struct session *s)
{
    if (!s || s->state == ST_DEAD)
        return;

    s->state = ST_DEAD;
    if (s->cssl)
        SSL_free(s->cssl);          /* frees its BIOs too */
    if (s->ossl)
        SSL_free(s->ossl);
    if (s->cfd >= 0) {
        by_fd[s->cfd] = NULL;
        ff_close(s->cfd);
    }
    if (s->ofd >= 0) {
        by_fd[s->ofd] = NULL;
        ff_close(s->ofd);
    }
    free(s);
}

static void fail(struct session *s, const char *why)
{
    stats.failed++;
    if (stats.failed <= 20)
        fprintf(stderr, "[poc] session failed in %s: %s\n",
                st_name[s->state], why);
    session_close(s);
}

/* ---- BIO pumping ------------------------------------------------------ */

/* Drain everything the SSL object wants to send onto the socket. */
static int pump_out(int fd, BIO *wbio)
{
    char buf[RELAY_BUF_SZ];
    int n;

    while ((n = BIO_read(wbio, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;

        while (off < n) {
            ssize_t w = ff_write(fd, buf + off, (size_t)(n - off));

            if (w > 0) {
                off += w;
                stats.tx_bytes += (unsigned long)w;
                continue;
            }
            if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                /*
                 * POC limitation: no send-side queue. A real implementation
                 * buffers the remainder and re-arms EVFILT_WRITE.
                 */
                return -1;
            }
            return -1;
        }
    }
    return 0;
}

/* Feed socket bytes into the SSL object's read BIO. Returns bytes moved,
 * 0 on peer close, -1 on error, -2 on EAGAIN. */
static int pump_in(int fd, BIO *rbio)
{
    char buf[RELAY_BUF_SZ];
    ssize_t n = ff_read(fd, buf, sizeof(buf));

    if (n > 0) {
        BIO_write(rbio, buf, (int)n);
        stats.rx_bytes += (unsigned long)n;
        return (int)n;
    }
    if (n == 0)
        return 0;
    if (errno == EAGAIN || errno == EWOULDBLOCK)
        return -2;
    return -1;
}

static int ssl_wants_more(SSL *ssl, int rc)
{
    int e = SSL_get_error(ssl, rc);

    return e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE;
}

/* ---- state transitions ------------------------------------------------ */

static int start_origin(struct session *s)
{
    int fd = ff_socket(AF_INET, SOCK_STREAM, 0);
    int rc;

    if (fd < 0 || fd >= POC_MAX_FD)
        return -1;

    set_nonblock(fd);
    s->ofd = fd;
    by_fd[fd] = s;

    rc = ff_connect(fd, (const struct linux_sockaddr *)&s->origin,
                    sizeof(s->origin));
    if (rc < 0 && errno != EINPROGRESS)
        return -1;

    if (kq_watch(s->kq, fd, EVFILT_WRITE, 1) < 0)
        return -1;
    s->state = ST_OCONNECT;
    return 0;
}

static int begin_origin_tls(struct session *s)
{
    if (!s->octx) {
        s->octx = SSL_CTX_new(TLS_client_method());
        if (!s->octx)
            return -1;
        SSL_CTX_set_min_proto_version(s->octx, TLS1_2_VERSION);
        /* POC: origin chain validation is out of scope. Production fails
         * closed on an invalid upstream chain -- see the design doc. */
        SSL_CTX_set_verify(s->octx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_mode(s->octx, SSL_MODE_RELEASE_BUFFERS);
    }

    s->ossl = SSL_new(s->octx);
    if (!s->ossl)
        return -1;
    s->orbio = BIO_new(BIO_s_mem());
    s->owbio = BIO_new(BIO_s_mem());
    if (!s->orbio || !s->owbio)
        return -1;
    BIO_set_mem_eof_return(s->orbio, -1);
    BIO_set_mem_eof_return(s->owbio, -1);
    SSL_set_bio(s->ossl, s->orbio, s->owbio);
    SSL_set_tlsext_host_name(s->ossl, s->sni);
    SSL_set_connect_state(s->ossl);

    if (kq_watch(s->kq, s->ofd, EVFILT_READ, 1) < 0)
        return -1;
    s->state = ST_OHS;
    return 0;
}

/* Origin handshake is done: forge the leaf and answer the client. */
static int begin_client_tls(struct session *s)
{
    X509 *mirror = SSL_get1_peer_certificate(s->ossl);
    SSL_CTX *sctx = forge_server_ctx(s->sni, mirror);

    if (mirror)
        X509_free(mirror);
    if (!sctx)
        return -1;

    s->cssl = SSL_new(sctx);
    if (!s->cssl)
        return -1;
    s->crbio = BIO_new(BIO_s_mem());
    s->cwbio = BIO_new(BIO_s_mem());
    if (!s->crbio || !s->cwbio)
        return -1;
    BIO_set_mem_eof_return(s->crbio, -1);
    BIO_set_mem_eof_return(s->cwbio, -1);
    SSL_set_bio(s->cssl, s->crbio, s->cwbio);
    SSL_set_accept_state(s->cssl);

    /* Replay the ClientHello we buffered before the origin leg existed.
     * This is the step a socket BIO could not do. */
    if (BIO_write(s->crbio, s->ch, (int)s->ch_len) != (int)s->ch_len)
        return -1;
    s->state = ST_CHS;
    return 0;
}

/* ---- relay ------------------------------------------------------------ */

/*
 * Move whatever is readable from one leg to the other.
 * Returns 0 to keep going, 1 when the source has closed cleanly,
 * -2 when the scan matched, -1 on a real error.
 */
static int relay_one(struct session *s, SSL *from, SSL *to, int to_fd,
                     BIO *to_wbio)
{
    uint8_t buf[RELAY_BUF_SZ];
    int n, e;

    while ((n = SSL_read(from, buf, sizeof(buf))) > 0) {
        int off = 0;

        if (scan_buf(buf, (size_t)n))
            return -2;          /* POC: drop the session on a match */
        while (off < n) {
            int w = SSL_write(to, buf + off, n - off);

            if (w > 0) {
                off += w;
                continue;
            }
            return -1;          /* POC: no re-drive queue */
        }
        if (pump_out(to_fd, to_wbio) < 0)
            return -1;
    }

    e = SSL_get_error(from, n);
    if (n == 0 || e == SSL_ERROR_ZERO_RETURN)
        return 1;               /* close_notify: an ordinary end of stream */
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
        return 0;
    return -1;
}

/*
 * One side finished, so close the other one properly: emit close_notify and
 * flush it, or the peer sees a truncated stream. Responses delimited by
 * connection close -- which is what s_server -www produces -- depend on this.
 */
/* A scan match is policy doing its job, not a failure. */
static void blocked(struct session *s)
{
    stats.blocked++;
    if (stats.blocked <= 20)
        fprintf(stderr, "[poc] blocked by scan: %s\n", s->sni);
    session_close(s);
}

static void finish(struct session *s)
{
    if (s->cssl) {
        SSL_shutdown(s->cssl);
        pump_out(s->cfd, s->cwbio);
    }
    if (s->ossl) {
        SSL_shutdown(s->ossl);
        pump_out(s->ofd, s->owbio);
    }
    stats.completed++;
    session_close(s);
}

/* ---- event entry point ------------------------------------------------ */

void session_event(struct session *s, int fd, int filter)
{
    int is_client = (fd == s->cfd);

    switch (s->state) {
    case ST_CH: {
        int n = pump_in_raw(s);

        if (n <= 0 && n != -2) {
            fail(s, "client closed before ClientHello");
            return;
        }
        switch (sni_parse(s->ch, s->ch_len, s->sni, sizeof(s->sni))) {
        case 1:
            if (start_origin(s) < 0)
                fail(s, "origin connect");
            return;
        case 0:
            if (s->ch_len >= CH_BUF_MAX)
                fail(s, "ClientHello too large");
            return;
        default:
            /* No SNI: production would fall back to IP-based policy or
             * splice. The POC has no destination without a name. */
            fail(s, "no SNI");
            return;
        }
    }

    case ST_OCONNECT: {
        int err = 0;
        socklen_t len = sizeof(err);

        if (ff_getsockopt(s->ofd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 ||
            err != 0) {
            fail(s, "origin unreachable");
            return;
        }
        kq_watch(s->kq, s->ofd, EVFILT_WRITE, 0);
        if (begin_origin_tls(s) < 0) {
            fail(s, "origin tls setup");
            return;
        }
        /* fall through to drive the handshake */
    }
    /* FALLTHROUGH */

    case ST_OHS: {
        int rc;

        if (!is_client) {
            int n = pump_in(s->ofd, s->orbio);

            if (n == 0 || n == -1) {
                fail(s, "origin closed during handshake");
                return;
            }
        }
        rc = SSL_do_handshake(s->ossl);
        if (pump_out(s->ofd, s->owbio) < 0) {
            fail(s, "origin write");
            return;
        }
        if (rc == 1) {
            stats.origin_handshakes++;
            if (begin_client_tls(s) < 0) {
                fail(s, "forge leaf");
                return;
            }
            /* Drive the client handshake with the replayed ClientHello. */
            rc = SSL_do_handshake(s->cssl);
            if (pump_out(s->cfd, s->cwbio) < 0) {
                fail(s, "client write");
                return;
            }
            if (rc == 1) {
                s->state = ST_RELAY;
                stats.client_handshakes++;
            } else if (!ssl_wants_more(s->cssl, rc)) {
                fail(s, "client handshake");
            }
            return;
        }
        if (!ssl_wants_more(s->ossl, rc))
            fail(s, "origin handshake");
        return;
    }

    case ST_CHS: {
        int rc;

        if (is_client) {
            int n = pump_in(s->cfd, s->crbio);

            if (n == 0 || n == -1) {
                fail(s, "client closed during handshake");
                return;
            }
        }
        rc = SSL_do_handshake(s->cssl);
        if (pump_out(s->cfd, s->cwbio) < 0) {
            fail(s, "client write");
            return;
        }
        if (rc == 1) {
            stats.client_handshakes++;
            s->state = ST_RELAY;
            return;
        }
        if (!ssl_wants_more(s->cssl, rc))
            fail(s, "client handshake");
        return;
    }

    case ST_RELAY: {
        int n, r;

        if (is_client) {
            n = pump_in(s->cfd, s->crbio);
            if (n == -1) {
                fail(s, "client read error");
                return;
            }
            r = relay_one(s, s->cssl, s->ossl, s->ofd, s->owbio);
            if (n == 0)
                r = 1;          /* socket closed under us */
            if (r > 0)
                finish(s);
            else if (r == -2)
                blocked(s);
            else if (r < 0)
                fail(s, "relay to origin");
        } else {
            n = pump_in(s->ofd, s->orbio);
            if (n == -1) {
                fail(s, "origin read error");
                return;
            }
            r = relay_one(s, s->ossl, s->cssl, s->cfd, s->cwbio);
            if (n == 0)
                r = 1;
            if (r > 0)
                finish(s);
            else if (r == -2)
                blocked(s);
            else if (r < 0)
                fail(s, "relay to client");
        }
        return;
    }

    default:
        return;
    }
}

/* Raw read used only while buffering the ClientHello, before any SSL
 * object exists on the client leg. */
int pump_in_raw(struct session *s)
{
    ssize_t n;

    if (s->ch_len >= CH_BUF_MAX)
        return -1;
    n = ff_read(s->cfd, s->ch + s->ch_len, CH_BUF_MAX - s->ch_len);
    if (n > 0) {
        s->ch_len += (size_t)n;
        stats.rx_bytes += (unsigned long)n;
        return (int)n;
    }
    if (n == 0)
        return 0;
    if (errno == EAGAIN || errno == EWOULDBLOCK)
        return -2;
    return -1;
}
