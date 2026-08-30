/*
 * Host-side tests for the parts of the POC that do not need F-Stack:
 * the ClientHello SNI parser and the certificate factory. Runs anywhere
 * OpenSSL is available, so these paths are verified before the DPDK box.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "proxy.h"

static int fails;

static void ok(const char *what, int cond)
{
    printf("  %-52s %s\n", what, cond ? "ok" : "FAIL");
    if (!cond)
        fails++;
}

/* Produce genuine ClientHello bytes by driving a real OpenSSL client. */
static int make_client_hello(const char *host, uint8_t *out, size_t cap,
                             size_t *outlen)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl;
    BIO *rbio, *wbio;
    long n;
    char *data;

    if (!ctx)
        return -1;
    ssl = SSL_new(ctx);
    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl, rbio, wbio);
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set_connect_state(ssl);
    SSL_do_handshake(ssl);          /* emits ClientHello, then WANT_READ */

    n = BIO_get_mem_data(wbio, &data);
    if (n <= 0 || (size_t)n > cap) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(out, data, (size_t)n);
    *outlen = (size_t)n;
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}

static void test_sni(void)
{
    uint8_t ch[CH_BUF_MAX];
    size_t len;
    char sni[MAX_SNI_LEN];

    printf("\nclienthello sni parsing\n");

    if (make_client_hello("api.example.invalid", ch, sizeof(ch), &len) != 0) {
        ok("generate a real ClientHello", 0);
        return;
    }
    ok("generate a real ClientHello", 1);

    ok("parses sni from a complete ClientHello",
       sni_parse(ch, len, sni, sizeof(sni)) == 1 &&
       !strcmp(sni, "api.example.invalid"));

    /* Partial buffers must ask for more rather than guess. */
    ok("returns need-more on a truncated record",
       sni_parse(ch, 4, sni, sizeof(sni)) == 0);
    ok("returns need-more mid-ClientHello",
       sni_parse(ch, len / 2, sni, sizeof(sni)) == 0);

    {
        uint8_t junk[16];

        memset(junk, 0xff, sizeof(junk));
        ok("rejects non-handshake bytes",
           sni_parse(junk, sizeof(junk), sni, sizeof(sni)) == -1);
    }
}

/* Drive a handshake between two in-process SSL objects over a BIO pair. */
static int drive(SSL *a, SSL *b)
{
    int i;

    for (i = 0; i < 64; i++) {
        if (SSL_is_init_finished(a) && SSL_is_init_finished(b))
            return 0;
        if (!SSL_is_init_finished(a))
            SSL_do_handshake(a);
        if (!SSL_is_init_finished(b))
            SSL_do_handshake(b);
    }
    return -1;
}

/* X509_NAME_add_entry_by_txt spelled once, for the fixture above. */
static void set_cn_for_test(X509_NAME *name, const char *cn)
{
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)cn, -1, -1, 0);
}

static void test_forge(void)
{
    const char *host = "files.example.invalid";
    SSL_CTX *sctx, *cctx;
    unsigned long hits = 0, mints = 0;
    char capath[] = "poc_ca.pem";

    printf("\ncertificate factory\n");

    ok("forge_init creates a CA", forge_init() == 0);
    ok("CA exports as PEM", forge_export_ca(capath) == 0);

    sctx = forge_server_ctx(host, NULL);
    ok("mints a leaf for an SNI", sctx != NULL);
    if (!sctx)
        return;

    ok("second request is a cache hit",
       forge_server_ctx(host, NULL) == sctx);
    forge_stats(&hits, &mints);
    ok("one mint, one hit", mints == 1 && hits == 1);

    /* A client that trusts the POC CA must accept the forged leaf, with
     * hostname verification on: this is what a managed endpoint will do. */
    cctx = SSL_CTX_new(TLS_client_method());
    ok("client trusts the POC CA",
       SSL_CTX_load_verify_locations(cctx, capath, NULL) == 1);
    SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, NULL);

    {
        BIO *cb = NULL, *sb = NULL;
        SSL *cli = SSL_new(cctx);
        SSL *srv = SSL_new(sctx);
        int handshook, verified;

        BIO_new_bio_pair(&cb, 0, &sb, 0);
        SSL_set_bio(cli, cb, cb);
        SSL_set_bio(srv, sb, sb);
        SSL_set_tlsext_host_name(cli, host);
        SSL_set1_host(cli, host);
        SSL_set_connect_state(cli);
        SSL_set_accept_state(srv);

        handshook = drive(cli, srv) == 0;
        ok("handshake completes against the forged leaf", handshook);
        verified = SSL_get_verify_result(cli) == X509_V_OK;
        ok("client verifies chain and hostname", verified);
        if (!verified)
            printf("      verify_result=%ld\n", SSL_get_verify_result(cli));

        SSL_free(cli);
        SSL_free(srv);
    }

    /* Wrong hostname must fail, or the gateway is not authenticating. */
    {
        BIO *cb = NULL, *sb = NULL;
        SSL *cli = SSL_new(cctx);
        SSL *srv = SSL_new(sctx);

        BIO_new_bio_pair(&cb, 0, &sb, 0);
        SSL_set_bio(cli, cb, cb);
        SSL_set_bio(srv, sb, sb);
        SSL_set1_host(cli, "other.example.invalid");
        SSL_set_connect_state(cli);
        SSL_set_accept_state(srv);
        drive(cli, srv);
        ok("mismatched hostname is rejected",
           SSL_get_verify_result(cli) != X509_V_OK);
        SSL_free(cli);
        SSL_free(srv);
    }

    SSL_CTX_free(cctx);
    remove(capath);
    /*
     * Regression: an origin certificate whose dates have passed must not
     * produce a leaf that has also expired. Copying the origin's window did
     * exactly that, and only clients that verify ever noticed -- load
     * generators skip verification, so it stayed hidden under traffic.
     */
    {
        X509 *stale = X509_new();
        SSL_CTX *sctx2;

        X509_set_version(stale, 2);
        set_cn_for_test(X509_get_subject_name(stale), "stale.example.invalid");
        X509_gmtime_adj(X509_getm_notBefore(stale), -60L * 60 * 48);
        X509_gmtime_adj(X509_getm_notAfter(stale), -60L * 60 * 24);
        ok("test fixture really is expired",
           X509_cmp_current_time(X509_get0_notAfter(stale)) < 0);

        sctx2 = forge_server_ctx("stale.example.invalid", stale);
        ok("mints a leaf from an expired origin", sctx2 != NULL);
        if (sctx2) {
            X509 *leaf = SSL_CTX_get0_certificate(sctx2);

            ok("that leaf is valid now, not expired with the origin",
               leaf &&
               X509_cmp_current_time(X509_get0_notAfter(leaf)) > 0 &&
               X509_cmp_current_time(X509_get0_notBefore(leaf)) < 0);
        }
        X509_free(stale);
    }

    forge_fini();
}

static void test_scan(void)
{
    const char *hay = "POST /upload\r\n\r\ncard=4111111111111111&x=1";

    printf("\ninspection stub\n");
    ok("scan_init accepts a pattern", scan_init("4111111111111111") == 0);
    ok("matches inside a plaintext buffer",
       scan_buf((const uint8_t *)hay, strlen(hay)) == 1);
    ok("no false positive on clean text",
       scan_buf((const uint8_t *)"nothing to see", 14) == 0);
}

int main(void)
{
    printf("poc host tests (no F-Stack required)\n");
    test_sni();
    test_forge();
    test_scan();
    printf("\n%s\n", fails ? "FAILURES" : "all host tests passed");
    return fails ? 1 : 0;
}
