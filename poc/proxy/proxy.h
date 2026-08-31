/*
 * Egress inspection gateway - POC vertical slice.
 *
 * Single lcore, explicit listen (no transparent interception), origin-first
 * TLS handshake ordering, forged leaf from a POC CA, and a relay that runs a
 * scan over the plaintext in both directions.
 *
 * Deliberately out of scope: transparency, multi-core steering, HTTP/2,
 * policy, connection pooling, control plane. See poc/README.md.
 */

#ifndef POC_PROXY_H
#define POC_PROXY_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/ssl.h>

#define CH_BUF_MAX      16384   /* enough for any ClientHello */
#define RELAY_BUF_SZ    16384   /* one TLS record */
/*
 * Bytes one leg may move before handing control back. On a run-to-completion
 * stack the application and the stack share a thread, so draining a whole
 * large transfer inside one callback keeps the stack from polling the NIC and
 * from transmitting what has already been queued.
 */
#define RELAY_BUDGET_DEFAULT (16 * RELAY_BUF_SZ)
extern size_t relay_budget;     /* set once at startup from POC_RELAY_BUDGET */
#define MAX_SNI_LEN     256

/* ---- ClientHello SNI parsing (sni.c) ---------------------------------- */

/*
 * Parse the SNI out of a buffered TLS ClientHello.
 *
 * Returns  1 on success (sni filled, NUL terminated),
 *          0 if more bytes are needed,
 *         -1 if this is not a ClientHello or carries no usable SNI.
 */
int sni_parse(const uint8_t *buf, size_t len, char *sni, size_t sni_cap);

/* ---- certificate forging (forge.c) ----------------------------------- */

/* Creates the POC CA. Returns 0 on success. */
int forge_init(void);
void forge_fini(void);

/*
 * Return an SSL_CTX serving a leaf for `sni`, minted on first use and cached
 * thereafter. `mirror` may carry the origin's certificate, whose subject and
 * SANs are copied when present. Returns NULL on failure.
 */
SSL_CTX *forge_server_ctx(const char *sni, X509 *mirror);

/* Write the POC CA in PEM form so a test client can trust it. */
int forge_export_ca(const char *path);

/* Cache statistics, for the POC report. */
void forge_stats(unsigned long *hits, unsigned long *mints);

/* ---- inspection (scan.c) --------------------------------------------- */

int scan_init(const char *pattern);
/* Returns 1 if the buffer matches (i.e. would be blocked), else 0. */
int scan_buf(const uint8_t *buf, size_t len);
void scan_stats(unsigned long *bytes, unsigned long *hits);

#endif /* POC_PROXY_H */
