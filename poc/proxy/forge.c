/* POC certificate factory: one in-memory EC CA, leaves minted per SNI and
 * cached. Mirrors the origin subject/SANs when the origin cert is available,
 * which is what origin-first handshake ordering buys. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "proxy.h"

#define FORGE_CACHE_MAX 4096

struct forge_entry {
    char sni[MAX_SNI_LEN];
    SSL_CTX *ctx;
};

static EVP_PKEY *ca_key;
static X509 *ca_crt;
/* One leaf key reused across all forged certs: saves a keygen per mint and
 * stays inside our own trust boundary. */
static EVP_PKEY *leaf_key;
static struct forge_entry cache[FORGE_CACHE_MAX];
static int cache_n;
static unsigned long stat_hits, stat_mints;

static EVP_PKEY *gen_p256(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    if (!ctx)
        return NULL;
    if (EVP_PKEY_keygen_init(ctx) != 1 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx,
            NID_X9_62_prime256v1) != 1 ||
        EVP_PKEY_keygen(ctx, &pkey) != 1)
        pkey = NULL;

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static void set_cn(X509_NAME *name, const char *cn)
{
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)cn, -1, -1, 0);
}

int forge_init(void)
{
    X509_NAME *name;

    ca_key = gen_p256();
    leaf_key = gen_p256();
    ca_crt = X509_new();
    if (!ca_key || !leaf_key || !ca_crt)
        return -1;

    X509_set_version(ca_crt, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(ca_crt), 1);
    X509_gmtime_adj(X509_getm_notBefore(ca_crt), 0);
    X509_gmtime_adj(X509_getm_notAfter(ca_crt), 60L * 60 * 24 * 30);
    X509_set_pubkey(ca_crt, ca_key);

    name = X509_get_subject_name(ca_crt);
    set_cn(name, "egress-inspection-gateway POC CA");
    X509_set_issuer_name(ca_crt, name);

    {
        X509_EXTENSION *ext;
        X509V3_CTX ctx;

        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, ca_crt, ca_crt, NULL, NULL, 0);
        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints,
                                  "critical,CA:TRUE");
        if (ext) {
            X509_add_ext(ca_crt, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    if (X509_sign(ca_crt, ca_key, EVP_sha256()) == 0)
        return -1;
    return 0;
}

void forge_fini(void)
{
    int i;

    for (i = 0; i < cache_n; i++)
        SSL_CTX_free(cache[i].ctx);
    cache_n = 0;
    X509_free(ca_crt);
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(leaf_key);
    ca_crt = NULL;
    ca_key = leaf_key = NULL;
}

/* Write the POC CA to a PEM file so a test client can trust it. */
int forge_export_ca(const char *path)
{
    FILE *f = fopen(path, "w");
    int ok;

    if (!f)
        return -1;
    ok = PEM_write_X509(f, ca_crt);
    fclose(f);
    return ok == 1 ? 0 : -1;
}

static X509 *mint_leaf(const char *sni, X509 *mirror)
{
    X509 *leaf = X509_new();
    X509_NAME *subject;
    char san[MAX_SNI_LEN + 8];

    if (!leaf)
        return NULL;

    X509_set_version(leaf, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(leaf), (long)(stat_mints + 2));
    X509_set_pubkey(leaf, leaf_key);
    X509_set_issuer_name(leaf, X509_get_subject_name(ca_crt));

    if (mirror) {
        /* Mirror the origin's subject and validity window. */
        X509_set_subject_name(leaf, X509_get_subject_name(mirror));
        ASN1_TIME_set_string(X509_getm_notBefore(leaf),
            (const char *)ASN1_STRING_get0_data(X509_get0_notBefore(mirror)));
        ASN1_TIME_set_string(X509_getm_notAfter(leaf),
            (const char *)ASN1_STRING_get0_data(X509_get0_notAfter(mirror)));
    } else {
        subject = X509_get_subject_name(leaf);
        set_cn(subject, sni);
        X509_gmtime_adj(X509_getm_notBefore(leaf), 0);
        X509_gmtime_adj(X509_getm_notAfter(leaf), 60L * 60 * 24);
    }

    /* SAN must carry the SNI regardless of what the origin said, or clients
     * reject the leaf. */
    snprintf(san, sizeof(san), "DNS:%s", sni);
    {
        X509_EXTENSION *ext;
        X509V3_CTX ctx;

        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, ca_crt, leaf, NULL, NULL, 0);
        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san);
        if (ext) {
            X509_add_ext(leaf, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    if (X509_sign(leaf, ca_key, EVP_sha256()) == 0) {
        X509_free(leaf);
        return NULL;
    }
    stat_mints++;
    return leaf;
}

SSL_CTX *forge_server_ctx(const char *sni, X509 *mirror)
{
    SSL_CTX *ctx;
    X509 *leaf;
    int i;

    for (i = 0; i < cache_n; i++) {
        if (!strcmp(cache[i].sni, sni)) {
            stat_hits++;
            return cache[i].ctx;
        }
    }

    leaf = mint_leaf(sni, mirror);
    if (!leaf)
        return NULL;

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        X509_free(leaf);
        return NULL;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate(ctx, leaf) != 1 ||
        SSL_CTX_use_PrivateKey(ctx, leaf_key) != 1 ||
        SSL_CTX_add_extra_chain_cert(ctx, X509_dup(ca_crt)) != 1) {
        SSL_CTX_free(ctx);
        X509_free(leaf);
        return NULL;
    }
    X509_free(leaf);
    /* Idle sessions holding record buffers is the 1M-session memory problem. */
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

    if (cache_n < FORGE_CACHE_MAX) {
        snprintf(cache[cache_n].sni, MAX_SNI_LEN, "%s", sni);
        cache[cache_n].ctx = ctx;
        cache_n++;
    }
    return ctx;
}

void forge_stats(unsigned long *hits, unsigned long *mints)
{
    if (hits)
        *hits = stat_hits;
    if (mints)
        *mints = stat_mints;
}
