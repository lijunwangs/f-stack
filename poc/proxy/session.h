#ifndef POC_SESSION_H
#define POC_SESSION_H

#include <stdlib.h>
#include <netinet/in.h>

#include <openssl/ssl.h>

#include "proxy.h"

/* Sized to cover fd_reserve plus the POC's session count. */
#define POC_MAX_FD 65536

/*
 * Send-side queue for one leg. The write BIO is memory, so SSL_write never
 * blocks; the socket does. When a write fills the socket, the remainder of
 * the chunk waits here and write interest stays armed until it drains.
 * One chunk is enough because pump_out stops pulling from the BIO as soon
 * as a write comes up short.
 */
struct outq {
    uint8_t buf[RELAY_BUF_SZ];
    size_t len;
    size_t off;
};

struct session {
    int kq;
    int cfd;
    int ofd;
    int state;
    struct sockaddr_in origin;

    struct outq cq, oq;         /* pending output, client and origin legs */
    int cmask, omask;           /* event interest currently registered */
    int closing;                /* stream ended; close once output drains */
    int in_pending;             /* queued for another relay visit */
    unsigned long moved;        /* plaintext bytes relayed, for stall detection */
    unsigned long moved_seen;   /* value at the last stall check */
    int stalls;                 /* consecutive checks with no progress */

    uint8_t ch[CH_BUF_MAX];     /* buffered ClientHello, replayed later */
    size_t ch_len;
    char sni[MAX_SNI_LEN];

    SSL_CTX *octx;              /* origin-leg client context */
    SSL *cssl;                  /* client leg: we are the server */
    SSL *ossl;                  /* origin leg: we are the client */
    BIO *crbio, *cwbio;
    BIO *orbio, *owbio;
};

struct poc_stats {
    unsigned long sessions;
    unsigned long origin_handshakes;
    unsigned long client_handshakes;
    unsigned long completed;
    unsigned long failed;
    unsigned long blocked;
    unsigned long rx_bytes;
    unsigned long tx_bytes;
    unsigned long tx_block;     /* writes deferred: socket full */
    unsigned long tx_nobufs;    /* writes deferred: stack out of mbufs */
};

struct session *session_new(int kq, int cfd, const struct sockaddr_in *origin);
struct session *session_lookup(int fd);
void session_event(struct session *s, int fd, int filter);
void session_close(struct session *s);
struct poc_stats *session_stats(void);
int pump_in_raw(struct session *s);
/*
 * Give sessions that stopped on their work budget another turn. The event
 * loop must call this once per iteration: on a run-to-completion stack the
 * application shares its thread with the stack, so the relay returns before
 * a large transfer is done and resumes here.
 */
void session_run_pending(void);
/* Non-zero when a session is waiting for another visit. */
int session_pending(void);
/*
 * Name any session that is in RELAY and has moved nothing for two checks,
 * dumping the state that decides whether it can ever wake: what each leg is
 * registered for, what is still queued, and what the write BIOs still hold.
 * A session waiting on a wakeup that will not come looks exactly like an idle
 * one from outside, and this is the difference.
 */
void session_report_stalled(void);

#endif /* POC_SESSION_H */
