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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "net.h"
#include "prof.h"
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

size_t relay_budget = RELAY_BUDGET_DEFAULT;

static struct session *by_fd[POC_MAX_FD];
static struct poc_stats stats;

/*
 * Sessions that stopped on their work budget and owe another visit. Held as
 * client fds rather than pointers so an entry closed before its turn simply
 * looks up as absent, with no dangling pointer to guard against.
 */
static int pending[POC_MAX_FD];
static int pending_n;

struct poc_stats *session_stats(void) { return &stats; }



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

    net_set_nonblock(cfd);
    by_fd[cfd] = s;
    if (ev_set(kq, cfd, NET_EV_READ) < 0) {
        session_close(s);
        return NULL;
    }
    s->cmask = NET_EV_READ;
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
        net_close(s->cfd);
    }
    if (s->ofd >= 0) {
        by_fd[s->ofd] = NULL;
        net_close(s->ofd);
    }
    free(s);
}

static void fail(struct session *s, const char *why)
{
    /* errno is worth printing: the stacks disagree about which failures are
     * transient, and the name of the one that fired is the whole diagnosis. */
    int e = errno;

    stats.failed++;
    if (stats.failed <= 20)
        fprintf(stderr, "[poc] session failed in %s: %s (errno %d: %s)\n",
                st_name[s->state], why, e, strerror(e));
    session_close(s);
}

static void mark_pending(struct session *s);

/* ---- BIO pumping ------------------------------------------------------ */

/*
 * Recompute what each leg should be woken for. Readiness is level-triggered,
 * so anything left unread is re-reported every iteration: a leg whose peer
 * cannot take more must stop asking to read, or the loop spins at full speed
 * getting told about data it is not allowed to move yet. Watching a leg whose
 * SSL object does not exist yet would spin the same way, hence the states.
 */
static void update_interest(struct session *s)
{
    int cong_c = s->cq.off < s->cq.len;   /* client leg output stuck */
    int cong_o = s->oq.off < s->oq.len;   /* origin leg output stuck */
    int cm, om;

    switch (s->state) {
    case ST_OHS:
        cm = 0;                           /* client leg has no SSL object yet */
        om = NET_EV_READ | (cong_o ? NET_EV_WRITE : 0);
        break;
    case ST_CHS:
        cm = NET_EV_READ | (cong_c ? NET_EV_WRITE : 0);
        om = 0;
        break;
    case ST_RELAY:
        if (s->closing) {                 /* only flushing what is owed */
            cm = cong_c ? NET_EV_WRITE : 0;
            om = cong_o ? NET_EV_WRITE : 0;
            break;
        }
        cm = (cong_o ? 0 : NET_EV_READ) | (cong_c ? NET_EV_WRITE : 0);
        om = (cong_c ? 0 : NET_EV_READ) | (cong_o ? NET_EV_WRITE : 0);
        break;
    default:
        return;
    }

    if (cm != s->cmask) {
        int rc;

        PROF_V(P_EVSET, rc, ev_set(s->kq, s->cfd, cm));
        if (rc == 0)
            s->cmask = cm;
    }
    if (s->ofd >= 0 && om != s->omask) {
        int rc;

        PROF_V(P_EVSET, rc, ev_set(s->kq, s->ofd, om));
        if (rc == 0)
            s->omask = om;
    }
}

/* Push the queued chunk out. 0 = emptied, 1 = socket full, -1 = error. */
static int flush_q(int fd, struct outq *q)
{
    while (q->off < q->len) {
        ssize_t w;

        PROF_V(P_SOCKWR, w, net_write(fd, q->buf + q->off, q->len - q->off));

        if (w > 0) {
            q->off += (size_t)w;
            stats.tx_bytes += (unsigned long)w;
            continue;
        }
        if (w < 0 && errno == EINTR)
            continue;
        /*
         * ENOBUFS belongs here with EAGAIN. The FreeBSD stack raises it when
         * mbufs are momentarily short, which is backpressure and clears on
         * its own; treating it as fatal killed sessions mid-transfer under
         * load, and the client simply reconnected and hit it again.
         */
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            stats.tx_block++;
            return 1;
        }
        if (w < 0 && errno == ENOBUFS) {
            stats.tx_nobufs++;
            return 1;
        }
        return -1;
    }
    q->len = q->off = 0;
    return 0;
}

/*
 * Drain everything the SSL object wants to send onto the socket, staging it
 * through the leg's queue so a short write costs no data.
 * 0 = nothing left to send, 1 = socket full and a chunk is still queued,
 * -1 = error. A full socket is backpressure, not a failure: callers stop
 * feeding this leg and the write event brings them back.
 */
static int pump_out(struct session *s, int fd, BIO *wbio, struct outq *q)
{
    int rc = flush_q(fd, q);

    while (rc == 0) {
        int n = BIO_read(wbio, q->buf, sizeof(q->buf));

        if (n <= 0)
            break;              /* memory BIO drained */
        q->len = (size_t)n;
        q->off = 0;
        rc = flush_q(fd, q);
    }
    if (rc >= 0)
        update_interest(s);
    /*
     * A congested leg puts itself back on the resume queue instead of waiting
     * to be told the socket drained. Relying on that notification deadlocked:
     * the relay would hand back one full response, mute the leg it could not
     * feed, and then sit forever because the write readiness it was waiting
     * for never arrived. Only nginx timing the idle connection out sixty
     * seconds later broke the cycle. Re-queueing costs a revisit that finds
     * nothing to do; the deadlock cost the whole session.
     */
    if (rc == 1)
        mark_pending(s);
    return rc;
}

/* Anything still owed to either peer? */
static int out_pending(struct session *s)
{
    if (s->cq.off < s->cq.len || s->oq.off < s->oq.len)
        return 1;
    if (s->cwbio && BIO_pending(s->cwbio) > 0)
        return 1;
    if (s->owbio && BIO_pending(s->owbio) > 0)
        return 1;
    return 0;
}

/* Feed socket bytes into the SSL object's read BIO. Returns bytes moved,
 * 0 on peer close, -1 on error, -2 on EAGAIN. */
static int pump_in(int fd, BIO *rbio)
{
    char buf[RELAY_BUF_SZ];
    ssize_t n;

    PROF_V(P_SOCKRD, n, net_read(fd, buf, sizeof(buf)));
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

/*
 * Drain the socket into the SSL object's read BIO, so a handshake message
 * split across segments completes on the wakeup that carried its last piece
 * rather than waiting for another. Handshakes are small and bounded, so this
 * one runs to completion. Returns 1 normally, 0 on peer close, -1 on error.
 */
static int fill_in(int fd, BIO *rbio)
{
    for (;;) {
        int n = pump_in(fd, rbio);

        if (n > 0)
            continue;
        if (n == -2)
            return 1;           /* socket drained */
        return n == 0 ? 0 : -1;
    }
}

static int ssl_wants_more(SSL *ssl, int rc)
{
    int e = SSL_get_error(ssl, rc);

    return e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE;
}

/* ---- state transitions ------------------------------------------------ */

static int start_origin(struct session *s)
{
    int fd = net_socket(AF_INET, SOCK_STREAM, 0);
    int rc;

    if (fd < 0 || fd >= POC_MAX_FD)
        return -1;

    net_set_nonblock(fd);
    s->ofd = fd;
    by_fd[fd] = s;

    rc = net_connect(fd, (const struct sockaddr *)&s->origin,
                     sizeof(s->origin));
    if (rc < 0 && errno != EINPROGRESS)
        return -1;

    if (ev_set(s->kq, fd, NET_EV_WRITE) < 0)
        return -1;
    s->omask = NET_EV_WRITE;
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

    if (ev_set(s->kq, s->ofd, NET_EV_READ) < 0)
        return -1;
    s->omask = NET_EV_READ;
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
 * Move up to a budget's worth from one leg to the other, refilling the source
 * socket as the SSL object runs dry. Both halves matter: reading only once per
 * wakeup strands the rest of a large transfer, while draining it all in one
 * visit starves a stack that shares this thread. So it drains, but only so far.
 *
 * Returns 0 when the source is exhausted or the peer pushed back, 1 when the
 * source has ended, 2 when the budget ran out and more may remain, -2 when the
 * scan matched, -1 on a real error.
 */
static int relay_one(struct session *s, SSL *from, int from_fd, BIO *from_rbio,
                     SSL *to, int to_fd, BIO *to_wbio, struct outq *to_q)
{
    uint8_t buf[RELAY_BUF_SZ];
    size_t moved = 0;

    for (;;) {
        int n, e, rc, off = 0;

        /*
         * Don't pull more plaintext while the far socket is congested.
         * SSL_write into a memory BIO always succeeds, so reading on would
         * grow that BIO without bound instead of pushing back on the source.
         */
        if (to_q->off < to_q->len)
            return 0;

        PROF_V(P_SSLRD, n, SSL_read(from, buf, sizeof(buf)));
        if (n > 0) {
            int hit;

            PROF_V(P_SCAN, hit, scan_buf(buf, (size_t)n));
            if (hit)
                return -2;      /* POC: drop the session on a match */
            while (off < n) {
                int w;

                PROF_V(P_SSLWR, w, SSL_write(to, buf + off, n - off));

                if (w <= 0)
                    return -1;  /* memory BIO: only a real error lands here */
                off += w;
            }
            s->moved += (unsigned long)n;
            rc = pump_out(s, to_fd, to_wbio, to_q);
            if (rc < 0)
                return -1;
            if (rc == 1)
                return 0;       /* congested; the write event resumes us */
            moved += (size_t)n;
            if (moved >= relay_budget)
                return 2;       /* yield to the stack, finish next visit */
            continue;
        }

        e = SSL_get_error(from, n);
        if (n == 0 || e == SSL_ERROR_ZERO_RETURN)
            return 1;           /* close_notify: an ordinary end of stream */
        if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
            return -1;

        /* The record layer wants more bytes: top it up from the socket. */
        n = pump_in(from_fd, from_rbio);
        if (n > 0)
            continue;
        if (n == 0)
            return 1;           /* peer closed without close_notify */
        if (n == -2)
            return 0;           /* socket drained */
        return -1;
    }
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
        pump_out(s, s->cfd, s->cwbio, &s->cq);
    }
    if (s->ossl && s->ofd >= 0) {
        SSL_shutdown(s->ossl);
        pump_out(s, s->ofd, s->owbio, &s->oq);
    }
    /*
     * Closing now would truncate whatever is still queued -- exactly what a
     * large response hits, since the tail is usually still in flight when the
     * source reports end of stream. Stay alive on write interest instead and
     * complete the close once the queues empty.
     */
    if (out_pending(s)) {
        s->closing = 1;
        return;
    }
    stats.completed++;
    session_close(s);
}

/* Queue this session for another relay visit, once. */
static void mark_pending(struct session *s)
{
    if (s->in_pending || pending_n >= POC_MAX_FD)
        return;
    s->in_pending = 1;
    pending[pending_n++] = s->cfd;
}

/*
 * Drain both directions once. Must be called whenever the session enters
 * RELAY, not only on a socket event: data can already be sitting in the read
 * BIO -- on loopback a client's Finished and its first request usually arrive
 * in the same segment -- and with edge-triggered readiness no further event
 * would ever come. Closes the session on completion or error, so callers must
 * not touch it afterwards.
 */
static void relay_pump(struct session *s)
{
    int r;

    /* A write event may have unblocked either leg; drain before reading on. */
    if (pump_out(s, s->cfd, s->cwbio, &s->cq) < 0) {
        fail(s, "client write");
        return;
    }
    if (s->ofd >= 0 && pump_out(s, s->ofd, s->owbio, &s->oq) < 0) {
        fail(s, "origin write");
        return;
    }
    if (s->closing) {
        if (!out_pending(s)) {
            stats.completed++;
            session_close(s);
        }
        return;
    }

    r = relay_one(s, s->cssl, s->cfd, s->crbio,
                  s->ossl, s->ofd, s->owbio, &s->oq);
    if (r == -2) {
        blocked(s);
        return;
    }
    if (r < 0) {
        fail(s, "relay to origin");
        return;
    }
    if (r == 1) {
        finish(s);
        return;
    }
    if (r == 2)
        mark_pending(s);

    r = relay_one(s, s->ossl, s->ofd, s->orbio,
                  s->cssl, s->cfd, s->cwbio, &s->cq);
    if (r == -2) {
        blocked(s);
        return;
    }
    if (r < 0) {
        fail(s, "relay to client");
        return;
    }
    if (r == 1) {
        finish(s);
        return;
    }
    if (r == 2)
        mark_pending(s);
    update_interest(s);
}

int session_pending(void) { return pending_n; }

void session_report_stalled(void)
{
    int fd, shown = 0;

    for (fd = 0; fd < POC_MAX_FD && shown < 4; fd++) {
        struct session *s = by_fd[fd];

        if (!s || s->cfd != fd || s->state != ST_RELAY)
            continue;           /* one entry per session, live relays only */
        if (s->moved != s->moved_seen) {
            s->moved_seen = s->moved;
            s->stalls = 0;
            continue;
        }
        /* One quiet interval is an idle keep-alive, not a stall. */
        if (++s->stalls < 2)
            continue;
        shown++;
        fprintf(stderr,
                "[poc] stalled cfd=%d ofd=%d for=%d checks | cmask=%d omask=%d"
                " | cq=%zu/%zu oq=%zu/%zu | cbio=%d obio=%d"
                " | pending=%d closing=%d\n",
                s->cfd, s->ofd, s->stalls, s->cmask, s->omask,
                s->cq.off, s->cq.len, s->oq.off, s->oq.len,
                s->cwbio ? BIO_pending(s->cwbio) : -1,
                s->owbio ? BIO_pending(s->owbio) : -1,
                s->in_pending, s->closing);
    }
}

void session_run_pending(void)
{
    int n = pending_n;
    int i;

    /*
     * Take the list as it stands: a session that runs out of budget again
     * re-queues itself for the next iteration rather than being retried here,
     * which is what keeps one big transfer from monopolising the thread.
     */
    pending_n = 0;
    for (i = 0; i < n; i++) {
        struct session *s = session_lookup(pending[i]);

        if (!s)
            continue;           /* closed before its turn */
        /*
         * Clear the flag before deciding whether to run, or a session queued
         * while it was still handshaking would keep the flag set for good and
         * could never be queued again -- the same stall by a slower route.
         */
        s->in_pending = 0;
        if (s->state != ST_RELAY)
            continue;
        relay_pump(s);
    }
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

        if (net_getsockopt(s->ofd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 ||
            err != 0) {
            fail(s, "origin unreachable");
            return;
        }
        /* begin_origin_tls sets the origin leg's interest to read only. */
        if (begin_origin_tls(s) < 0) {
            fail(s, "origin tls setup");
            return;
        }
        /* fall through to drive the handshake */
    }
    /* FALLTHROUGH */

    case ST_OHS: {
        int rc;

        if (!is_client && fill_in(s->ofd, s->orbio) <= 0) {
            fail(s, "origin closed during handshake");
            return;
        }
        PROF_V(P_HANDSHAKE, rc, SSL_do_handshake(s->ossl));
        if (pump_out(s, s->ofd, s->owbio, &s->oq) < 0) {
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
            PROF_V(P_HANDSHAKE, rc, SSL_do_handshake(s->cssl));
            if (pump_out(s, s->cfd, s->cwbio, &s->cq) < 0) {
                fail(s, "client write");
                return;
            }
            if (rc == 1) {
                s->state = ST_RELAY;
                stats.client_handshakes++;
                relay_pump(s);
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

        if (is_client && fill_in(s->cfd, s->crbio) <= 0) {
            fail(s, "client closed during handshake");
            return;
        }
        PROF_V(P_HANDSHAKE, rc, SSL_do_handshake(s->cssl));
        if (pump_out(s, s->cfd, s->cwbio, &s->cq) < 0) {
            fail(s, "client write");
            return;
        }
        if (rc == 1) {
            stats.client_handshakes++;
            s->state = ST_RELAY;
            relay_pump(s);
            return;
        }
        if (!ssl_wants_more(s->cssl, rc))
            fail(s, "client handshake");
        return;
    }

    case ST_RELAY:
        relay_pump(s);
        return;

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
    n = net_read(s->cfd, s->ch + s->ch_len, CH_BUF_MAX - s->ch_len);
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
