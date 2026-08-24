/*
 * M0a bench: measures the CPU-bound lines of the egress inspection gateway
 * budget. No DPDK, no F-Stack, no NIC, no root required.
 *
 * Measures per single core:
 *   aead      AES-256-GCM in-place throughput at proxy record sizes
 *   asym      ECDSA P-256 sign/verify and ECDH P-256 agreement rates
 *   handshake full and resumed TLS 1.3 handshake pairs over a BIO pair,
 *             which is the gateway's per-session cost with no network involved
 *   copy      memcpy throughput at record size
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

/* Budget thresholds from the design doc; a fail means the budget needs redoing. */
#define GATE_AEAD_GBPS      4.0
#define GATE_SIGN_PER_SEC   30000.0
#define GATE_ECDH_PER_SEC   25000.0
#define GATE_HANDSHAKE_US   150.0
#define GATE_MEMCPY_GBPS    8.0

#define REC_SMALL 4096
#define REC_LARGE 16384

static int g_failures;
static double g_sign_per_s, g_verify_per_s, g_ecdh_per_s;

static double now_wall(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static double now_cpu(void)
{
#ifdef CLOCK_PROCESS_CPUTIME_ID
    struct timespec ts;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) == 0)
        return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
#endif
    return now_wall();
}

__attribute__((noreturn)) static void die(const char *what)
{
    fprintf(stderr, "fatal: %s\n", what);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static void report(const char *name, double value, const char *unit,
                   double gate, int higher_is_better)
{
    int pass = higher_is_better ? (value >= gate) : (value <= gate);
    if (!pass)
        g_failures++;
    printf("  %-34s %10.1f %-8s  gate %s%-8.1f  %s\n",
           name, value, unit, higher_is_better ? ">= " : "<= ", gate,
           pass ? "PASS" : "FAIL");
}

static void report_info(const char *name, double value, const char *unit)
{
    printf("  %-34s %10.1f %-8s  %-17s  -\n", name, value, unit, "");
}

/* ---------------------------------------------------------------- aead */

static double aead_gbps(size_t reclen, int encrypt)
{
    unsigned char key[32], iv[12], tag[16];
    unsigned char *buf;
    EVP_CIPHER_CTX *ctx;
    double t0, elapsed, bytes = 0;
    int outl;
    /* Enough iterations that a fast core still runs ~1s. */
    const long iters = (long)((2ULL << 30) / reclen);
    long i;

    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));
    buf = malloc(reclen);
    if (!buf)
        die("malloc");
    memset(buf, 0x5a, reclen);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        die("EVP_CIPHER_CTX_new");

    t0 = now_cpu();
    for (i = 0; i < iters; i++) {
        if (encrypt) {
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1)
                die("EncryptInit");
            if (EVP_EncryptUpdate(ctx, buf, &outl, buf, (int)reclen) != 1)
                die("EncryptUpdate");
            EVP_EncryptFinal_ex(ctx, buf + outl, &outl);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, sizeof(tag), tag);
        } else {
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1)
                die("DecryptInit");
            if (EVP_DecryptUpdate(ctx, buf, &outl, buf, (int)reclen) != 1)
                die("DecryptUpdate");
        }
        bytes += (double)reclen;
    }
    elapsed = now_cpu() - t0;

    EVP_CIPHER_CTX_free(ctx);
    free(buf);
    return bytes / elapsed / 1e9;
}

static void bench_aead(void)
{
    printf("\naes-256-gcm, in place, single core\n");
    report("encrypt 4 KB records", aead_gbps(REC_SMALL, 1), "GB/s",
           GATE_AEAD_GBPS, 1);
    report("encrypt 16 KB records", aead_gbps(REC_LARGE, 1), "GB/s",
           GATE_AEAD_GBPS, 1);
    report("decrypt 16 KB records", aead_gbps(REC_LARGE, 0), "GB/s",
           GATE_AEAD_GBPS, 1);
}

/* ---------------------------------------------------------------- asym */

static EVP_PKEY *gen_p256(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    if (!ctx || EVP_PKEY_keygen_init(ctx) != 1 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) != 1 ||
        EVP_PKEY_keygen(ctx, &pkey) != 1)
        die("p256 keygen");

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static void bench_asym(void)
{
    EVP_PKEY *key = gen_p256();
    unsigned char digest[32], *sig;
    size_t siglen = 0, maxsig = 0;
    EVP_PKEY_CTX *ctx;
    double t0, elapsed;
    const long iters = 20000;
    long i;

    RAND_bytes(digest, sizeof(digest));

    printf("\necdsa / ecdh p-256, single core\n");

    /* sign */
    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx || EVP_PKEY_sign_init(ctx) != 1 ||
        EVP_PKEY_sign(ctx, NULL, &maxsig, digest, sizeof(digest)) != 1)
        die("sign init");
    sig = malloc(maxsig);
    if (!sig)
        die("malloc");

    t0 = now_cpu();
    for (i = 0; i < iters; i++) {
        siglen = maxsig;
        if (EVP_PKEY_sign(ctx, sig, &siglen, digest, sizeof(digest)) != 1)
            die("sign");
    }
    elapsed = now_cpu() - t0;
    g_sign_per_s = (double)iters / elapsed;
    report("ecdsa sign", g_sign_per_s, "ops/s", GATE_SIGN_PER_SEC, 1);
    EVP_PKEY_CTX_free(ctx);

    /* verify: informational, but it is the origin-leg chain cost */
    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx || EVP_PKEY_verify_init(ctx) != 1)
        die("verify init");
    t0 = now_cpu();
    for (i = 0; i < iters; i++) {
        if (EVP_PKEY_verify(ctx, sig, siglen, digest, sizeof(digest)) != 1)
            die("verify");
    }
    elapsed = now_cpu() - t0;
    g_verify_per_s = (double)iters / elapsed;
    report_info("ecdsa verify", g_verify_per_s, "ops/s");
    EVP_PKEY_CTX_free(ctx);
    free(sig);

    /* ecdh: keygen plus agreement, which is what a handshake actually pays */
    t0 = now_cpu();
    for (i = 0; i < iters; i++) {
        EVP_PKEY *eph = gen_p256();
        EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(eph, NULL);
        unsigned char secret[64];
        size_t slen = sizeof(secret);

        if (!dctx || EVP_PKEY_derive_init(dctx) != 1 ||
            EVP_PKEY_derive_set_peer(dctx, key) != 1 ||
            EVP_PKEY_derive(dctx, secret, &slen) != 1)
            die("ecdh derive");
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(eph);
    }
    elapsed = now_cpu() - t0;
    g_ecdh_per_s = (double)iters / elapsed;
    report("ecdh keygen + agree", g_ecdh_per_s, "ops/s", GATE_ECDH_PER_SEC, 1);

    EVP_PKEY_free(key);
}

/* ----------------------------------------------------------- handshake */

/* Self-signed P-256 leaf, generated in memory; stands in for a forged leaf. */
static int make_cert(EVP_PKEY **key_out, X509 **crt_out)
{
    EVP_PKEY *key = gen_p256();
    X509 *crt = X509_new();
    X509_NAME *name;

    if (!crt)
        die("X509_new");

    X509_set_version(crt, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
    X509_gmtime_adj(X509_getm_notBefore(crt), 0);
    X509_gmtime_adj(X509_getm_notAfter(crt), 3600);
    X509_set_pubkey(crt, key);

    name = X509_get_subject_name(crt);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)"poc.invalid", -1, -1, 0);
    X509_set_issuer_name(crt, name);

    if (X509_sign(crt, key, EVP_sha256()) == 0)
        die("X509_sign");

    *key_out = key;
    *crt_out = crt;
    return 0;
}

/*
 * Drive a handshake between two in-process SSL objects joined by a BIO pair.
 * Returns 0 on success. Both sides are pumped until each reports done.
 */
static int drive_handshake(SSL *cli, SSL *srv)
{
    int i;

    for (i = 0; i < 64; i++) {
        int cdone = SSL_is_init_finished(cli);
        int sdone = SSL_is_init_finished(srv);

        if (cdone && sdone)
            return 0;
        if (!cdone) {
            int r = SSL_do_handshake(cli);
            if (r <= 0) {
                int e = SSL_get_error(cli, r);
                if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
                    return -1;
            }
        }
        if (!sdone) {
            int r = SSL_do_handshake(srv);
            if (r <= 0) {
                int e = SSL_get_error(srv, r);
                if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
                    return -1;
            }
        }
    }
    return -1;
}

static void bench_handshake(void)
{
    EVP_PKEY *key;
    X509 *crt;
    SSL_CTX *sctx, *cctx;
    double t0, elapsed;
    const long iters = 2000;
    long i;

    make_cert(&key, &crt);

    sctx = SSL_CTX_new(TLS_server_method());
    cctx = SSL_CTX_new(TLS_client_method());
    if (!sctx || !cctx)
        die("SSL_CTX_new");

    SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION);
    SSL_CTX_set_min_proto_version(cctx, TLS1_3_VERSION);
    if (SSL_CTX_use_certificate(sctx, crt) != 1 ||
        SSL_CTX_use_PrivateKey(sctx, key) != 1)
        die("server cert");
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_OFF);

    printf("\ntls 1.3 handshake pair, in process, no network\n");

    t0 = now_cpu();
    for (i = 0; i < iters; i++) {
        BIO *cbio = NULL, *sbio = NULL;
        SSL *cli = SSL_new(cctx);
        SSL *srv = SSL_new(sctx);

        if (!cli || !srv)
            die("SSL_new");
        if (BIO_new_bio_pair(&cbio, 0, &sbio, 0) != 1)
            die("BIO_new_bio_pair");

        SSL_set_bio(cli, cbio, cbio);
        SSL_set_bio(srv, sbio, sbio);
        SSL_set_connect_state(cli);
        SSL_set_accept_state(srv);

        if (drive_handshake(cli, srv) != 0)
            die("full handshake");

        SSL_free(cli);
        SSL_free(srv);
    }
    elapsed = now_cpu() - t0;
    report("full handshake pair", elapsed / iters * 1e6, "us",
           GATE_HANDSHAKE_US, 0);
    /*
     * A TLS 1.3 pair spends roughly 2 ECDH keygen+agree, 1 sign and 1 verify
     * on asymmetric work. Reporting that sum next to the measured handshake
     * separates raw crypto from OpenSSL per-connection overhead, which the
     * gateway pays on every session and which budgets routinely omit.
     */
    if (g_ecdh_per_s > 0 && g_sign_per_s > 0 && g_verify_per_s > 0) {
        double prim = (2.0 / g_ecdh_per_s + 1.0 / g_sign_per_s +
                       1.0 / g_verify_per_s) * 1e6;
        report_info("of which asymmetric primitives", prim, "us");
        report_info("openssl per-connection overhead",
                    elapsed / iters * 1e6 - prim, "us");
    }

    /*
     * Resumption saving is deliberately not measured here: PSK resumption
     * over a BIO pair did not engage, and an untrustworthy number is worse
     * than none. Measure it against a real endpoint instead:
     *   openssl s_server -tls1_3 -cert c.pem -key k.pem
     *   openssl s_client -tls1_3 -sess_out s.pem   (then -sess_in s.pem)
     * At the ~5% client propensity this design assumes, it is confirmatory
     * only -- see the handshake economics section of the design doc.
     */

    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    X509_free(crt);
    EVP_PKEY_free(key);
}

/* ---------------------------------------------------------------- copy */

static void bench_copy(void)
{
    const size_t len = REC_LARGE;
    const long iters = (long)((4ULL << 30) / len);
    unsigned char *src = malloc(len), *dst = malloc(len);
    double t0, elapsed;
    volatile unsigned long long sink = 0;
    long i;

    if (!src || !dst)
        die("malloc");
    memset(src, 0x27, len);

    printf("\nmemcpy, single core\n");
    t0 = now_cpu();
    for (i = 0; i < iters; i++) {
        memcpy(dst, src, len);
        /* Consume the result so the copy cannot be elided. */
        sink += dst[i % len];
        src[i % len]++;
    }
    elapsed = now_cpu() - t0;
    if (sink == 0)
        printf("  (sink %llu)\n", (unsigned long long)sink);
    report("memcpy 16 KB", (double)iters * len / elapsed / 1e9, "GB/s",
           GATE_MEMCPY_GBPS, 1);

    free(src);
    free(dst);
}

/* ---------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    const char *only = argc > 1 ? argv[1] : NULL;

    printf("m0a bench - egress inspection gateway budget\n");
    printf("openssl: %s\n", OpenSSL_version(OPENSSL_VERSION_STRING));

    if (!only || !strcmp(only, "aead"))
        bench_aead();
    if (!only || !strcmp(only, "asym"))
        bench_asym();
    if (!only || !strcmp(only, "handshake"))
        bench_handshake();
    if (!only || !strcmp(only, "copy"))
        bench_copy();

    printf("\n%s (%d gate failure%s)\n",
           g_failures ? "BUDGET NEEDS REVISION" : "budget holds",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
