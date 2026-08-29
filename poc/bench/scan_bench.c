/*
 * M0b bench: inspection engine throughput, the line of the budget the TLS
 * bench does not cover. No DPDK, no F-Stack, no NIC, no root required.
 *
 * The gateway relays in fixed chunks, so a pattern can straddle a chunk
 * boundary. Two ways to not miss those:
 *
 *   overlap  block mode, carrying the last W bytes of each chunk into the
 *            next scan. W comes from the pattern set: a match can reach at
 *            most max_width bytes back, so W = max(max_width) - 1 is enough,
 *            and the engine reports max_width per expression. Patterns with
 *            no bound (anything with .*) cannot be covered this way at all,
 *            which this bench detects rather than assumes.
 *   stream   the engine keeps the state itself, catching everything, at the
 *            cost of hs_stream_size() bytes per stream. At a million sessions
 *            in both directions that is the number that decides it.
 *
 * Both are measured, and per-session memory is reported for each, because
 * the choice is a memory decision more than a throughput one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <limits.h>

#include <hs/hs.h>

/*
 * 70 Gbps of inspected traffic is 8.75 GB/s. The design doc budgets 4.4 cores
 * to inspection, so a core has to sustain about 2 GB/s for the budget to hold.
 */
#define GATE_SCAN_GBPS 2.0

#define CORPUS_BYTES (64u << 20)    /* 64 MB: past any cache, short enough to loop */
#define DEF_CHUNK    16384          /* the proxy's relay chunk */

enum { CLASS_LITERAL = 0, CLASS_BOUNDED, CLASS_UNBOUNDED, CLASS_N };

static const char *class_name[CLASS_N] = { "literal", "bounded", "unbounded" };

static int g_failures;

static double now_wall(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void die(const char *what)
{
    fprintf(stderr, "fatal: %s\n", what);
    exit(1);
}

static void report(const char *name, double value, const char *unit,
                   double gate, int higher_is_better)
{
    int pass = higher_is_better ? (value >= gate) : (value <= gate);

    if (!pass)
        g_failures++;
    printf("  %-34s %10.2f %-8s  gate %s%-8.2f  %s\n",
           name, value, unit, higher_is_better ? ">= " : "<= ", gate,
           pass ? "PASS" : "FAIL");
}

static void note(const char *name, double value, const char *unit)
{
    printf("  %-34s %10.2f %-8s  %-17s  -\n", name, value, unit, "");
}

/* ---- patterns --------------------------------------------------------- */

struct patset {
    char **expr;
    unsigned *flags;
    unsigned *ids;
    unsigned n;
};

static void patset_free(struct patset *p)
{
    unsigned i;

    for (i = 0; i < p->n; i++)
        free(p->expr[i]);
    free(p->expr);
    free(p->flags);
    free(p->ids);
    memset(p, 0, sizeof(*p));
}

static void patset_alloc(struct patset *p, unsigned n)
{
    p->expr = calloc(n, sizeof(*p->expr));
    p->flags = calloc(n, sizeof(*p->flags));
    p->ids = calloc(n, sizeof(*p->ids));
    if (!p->expr || !p->flags || !p->ids)
        die("out of memory");
    p->n = n;
}

/*
 * Synthetic sets standing in for a real DLP list. The classes matter more
 * than the count: the engine has a fast literal path, bounded repeats cost
 * more, and an unbounded pattern changes what is even possible.
 */
static void patset_synth(struct patset *p, int cls, unsigned n)
{
    unsigned i;
    char buf[160];

    patset_alloc(p, n);
    for (i = 0; i < n; i++) {
        switch (cls) {
        case CLASS_LITERAL:
            snprintf(buf, sizeof(buf), "CONFIDENTIAL-PROJECT-%06u", i);
            break;
        case CLASS_BOUNDED:
            /* PAN, SSN and access-key shapes, all bounded in length. */
            switch (i % 3) {
            case 0:
                snprintf(buf, sizeof(buf), "4%03u[0-9]{12}", i % 1000);
                break;
            case 1:
                snprintf(buf, sizeof(buf), "%03u-[0-9]{2}-[0-9]{4}", i % 1000);
                break;
            default:
                snprintf(buf, sizeof(buf), "AKIA%03u[0-9A-Z]{13}", i % 1000);
                break;
            }
            break;
        default:
            /* No bound: the reason overlap mode cannot always be used. */
            snprintf(buf, sizeof(buf), "BEGIN-%04u.*END", i);
            break;
        }
        p->expr[i] = strdup(buf);
        if (!p->expr[i])
            die("out of memory");
        p->flags[i] = HS_FLAG_DOTALL;
        p->ids[i] = i;
    }
}

static int patset_file(struct patset *p, const char *path)
{
    char line[4096];
    unsigned cap = 64, n = 0;
    FILE *f = fopen(path, "r");

    if (!f)
        return -1;
    patset_alloc(p, cap);
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);

        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (!len || line[0] == '#')
            continue;
        if (n == cap) {
            cap *= 2;
            p->expr = realloc(p->expr, cap * sizeof(*p->expr));
            p->flags = realloc(p->flags, cap * sizeof(*p->flags));
            p->ids = realloc(p->ids, cap * sizeof(*p->ids));
            if (!p->expr || !p->flags || !p->ids)
                die("out of memory");
        }
        p->expr[n] = strdup(line);
        if (!p->expr[n])
            die("out of memory");
        p->flags[n] = HS_FLAG_DOTALL;
        p->ids[n] = n;
        n++;
    }
    fclose(f);
    p->n = n;
    return n ? 0 : -1;
}

/*
 * Derive the overlap window from the patterns themselves. A match reaches at
 * most max_width bytes back from where it ends, so carrying max_width - 1
 * bytes into the next scan makes every straddling match visible. An
 * unbounded expression has no such distance and is reported as such: that is
 * a property of the pattern set, not a tuning knob, and it decides whether
 * block mode is usable at all.
 */
static int overlap_width(const struct patset *p, unsigned *out_w,
                         unsigned *out_unbounded)
{
    unsigned i, w = 0, unbounded = 0;

    for (i = 0; i < p->n; i++) {
        hs_expr_info_t *info = NULL;
        hs_compile_error_t *err = NULL;

        if (hs_expression_info(p->expr[i], p->flags[i], &info, &err) != HS_SUCCESS) {
            fprintf(stderr, "  cannot inspect '%s': %s\n", p->expr[i],
                    err && err->message ? err->message : "?");
            if (err)
                hs_free_compile_error(err);
            return -1;
        }
        if (info->max_width == UINT_MAX)
            unbounded++;
        else if (info->max_width > w)
            w = info->max_width;
        free(info);
    }
    *out_unbounded = unbounded;
    *out_w = w ? w - 1 : 0;
    return 0;
}

/* ---- corpus ----------------------------------------------------------- */

static uint32_t rnd_state = 12345;

static uint32_t rnd(void)
{
    rnd_state ^= rnd_state << 13;
    rnd_state ^= rnd_state >> 17;
    rnd_state ^= rnd_state << 5;
    return rnd_state;
}

/*
 * Printable filler with matches planted at a chosen rate. Clean traffic is
 * the case that decides capacity -- almost nothing a gateway inspects
 * matches -- so density 0 is the headline and the rest shows what a hit costs.
 */
static char *corpus_make(size_t len, int per_mb, int cls)
{
    char *buf = malloc(len + 1);
    size_t i, step;

    if (!buf)
        die("out of memory");
    for (i = 0; i < len; i++)
        buf[i] = (char)(' ' + (rnd() % 95));

    if (per_mb > 0) {
        char hit[64];
        size_t hlen;

        if (cls == CLASS_BOUNDED)
            snprintf(hit, sizeof(hit), "4000123456789012");
        else
            snprintf(hit, sizeof(hit), "CONFIDENTIAL-PROJECT-000000");
        hlen = strlen(hit);
        step = (size_t)((1u << 20) / per_mb);
        for (i = step; i + hlen < len; i += step)
            memcpy(buf + i, hit, hlen);
    }
    buf[len] = '\0';
    return buf;
}

/* ---- scanning --------------------------------------------------------- */

struct mctx {
    unsigned long long matches;
    unsigned long long suppressed;
    unsigned w;                 /* overlap prefix length, 0 in stream mode */
};

static int on_match(unsigned id, unsigned long long from, unsigned long long to,
                    unsigned flags, void *ctx)
{
    struct mctx *m = ctx;

    /*
     * A match ending inside the carried prefix was already reported when
     * those bytes were the new part of a scan, so it is a duplicate rather
     * than a find. The proxy kills the session on the first hit and would
     * never notice, but a counting bench has to.
     */
    if (m->w && to <= m->w) {
        m->suppressed++;
        return 0;
    }
    m->matches++;
    return 0;
}

/* Block mode carrying a W-byte tail between chunks. Returns GB/s of payload. */
static double run_overlap(const hs_database_t *db, hs_scratch_t *scratch,
                          const char *corpus, size_t len, size_t chunk,
                          unsigned w, struct mctx *m)
{
    char *staging = malloc(chunk + w);
    size_t off = 0, tail = 0;
    double t0, dt;

    if (!staging)
        die("out of memory");
    t0 = now_wall();
    while (off < len) {
        size_t n = len - off < chunk ? len - off : chunk;
        size_t have, keep;

        /*
         * Copy the carried tail in front of the new chunk. The proxy's chunks
         * are separate buffers, so this copy is part of the real cost and is
         * inside the timed region deliberately.
         */
        memcpy(staging + tail, corpus + off, n);
        have = tail + n;
        m->w = (unsigned)tail;      /* bytes already scanned last round */
        if (hs_scan(db, staging, (unsigned)have, 0, scratch,
                    on_match, m) != HS_SUCCESS)
            die("hs_scan failed");
        off += n;

        keep = have < w ? have : w;
        if (keep)
            memmove(staging, staging + have - keep, keep);
        tail = keep;
    }
    dt = now_wall() - t0;
    free(staging);
    return (double)len / dt / 1e9;
}

/* Streaming mode: one stream stands in for one session direction. */
static double run_stream(const hs_database_t *db, hs_scratch_t *scratch,
                         const char *corpus, size_t len, size_t chunk,
                         struct mctx *m)
{
    hs_stream_t *st = NULL;
    size_t off = 0;
    double t0, dt;

    m->w = 0;
    if (hs_open_stream(db, 0, &st) != HS_SUCCESS)
        die("hs_open_stream failed");
    t0 = now_wall();
    while (off < len) {
        size_t n = len - off < chunk ? len - off : chunk;

        if (hs_scan_stream(st, corpus + off, (unsigned)n, 0, scratch,
                           on_match, m) != HS_SUCCESS)
            die("hs_scan_stream failed");
        off += n;
    }
    dt = now_wall() - t0;
    hs_close_stream(st, scratch, on_match, m);
    return (double)len / dt / 1e9;
}

static hs_database_t *compile(const struct patset *p, unsigned mode)
{
    hs_database_t *db = NULL;
    hs_compile_error_t *err = NULL;
    double t0 = now_wall();

    if (hs_compile_multi((const char *const *)p->expr, p->flags, p->ids,
                         p->n, mode, NULL, &db, &err) != HS_SUCCESS) {
        fprintf(stderr, "  compile failed: %s\n",
                err && err->message ? err->message : "?");
        if (err)
            hs_free_compile_error(err);
        return NULL;
    }
    /*
     * Compile cost is reported because it decides where compiling belongs:
     * milliseconds to seconds is control-plane work, never an lcore's.
     */
    if (mode == HS_MODE_BLOCK && p->n >= 1000)
        printf("  (compiled %u patterns in %.2f s)\n", p->n, now_wall() - t0);
    return db;
}

/* ---- sweeps ----------------------------------------------------------- */

static void sweep_class_count(const char *corpus, size_t len, size_t chunk)
{
    static const unsigned counts[] = { 1, 10, 100, 1000 };
    unsigned ci, ki;

    printf("\nthroughput by pattern class and count, %zu-byte chunks, "
           "clean traffic\n", chunk);
    printf("  %-10s %8s %8s %10s %8s\n",
           "class", "patterns", "window", "GB/s", "db KB");
    for (ci = 0; ci < CLASS_N; ci++) {
        for (ki = 0; ki < sizeof(counts) / sizeof(counts[0]); ki++) {
            struct patset p;
            hs_database_t *db;
            hs_scratch_t *scratch = NULL;
            struct mctx m = { 0, 0, 0 };
            unsigned w = 0, unb = 0;
            size_t dbsz = 0;
            double gbps;

            patset_synth(&p, (int)ci, counts[ki]);
            if (overlap_width(&p, &w, &unb) < 0) {
                patset_free(&p);
                continue;
            }
            db = compile(&p, HS_MODE_BLOCK);
            if (!db) {
                patset_free(&p);
                continue;
            }
            hs_alloc_scratch(db, &scratch);
            hs_database_size(db, &dbsz);
            if (unb) {
                /* No finite window covers these; streaming is the only option. */
                printf("  %-10s %8u %8s %10s %8.1f   (unbounded: needs streaming)\n",
                       class_name[ci], counts[ki], "none", "-", dbsz / 1024.0);
            } else {
                gbps = run_overlap(db, scratch, corpus, len, chunk, w, &m);
                printf("  %-10s %8u %8u %10.2f %8.1f\n",
                       class_name[ci], counts[ki], w, gbps, dbsz / 1024.0);
            }
            hs_free_scratch(scratch);
            hs_free_database(db);
            patset_free(&p);
        }
    }
}

static void sweep_chunk(const char *corpus, size_t len, int cls, unsigned n)
{
    static const size_t chunks[] = { 1024, 4096, 16384, 65536 };
    unsigned i;
    struct patset p;
    unsigned w = 0, unb = 0;

    patset_synth(&p, cls, n);
    if (overlap_width(&p, &w, &unb) < 0 || unb) {
        patset_free(&p);
        return;
    }
    printf("\nthroughput by chunk size, %s x%u, window %u bytes\n",
           class_name[cls], n, w);
    printf("  %-10s %10s %12s\n", "chunk", "GB/s", "rescan cost");
    for (i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
        hs_database_t *db = compile(&p, HS_MODE_BLOCK);
        hs_scratch_t *scratch = NULL;
        struct mctx m = { 0, 0, 0 };
        double gbps;

        if (!db)
            break;
        hs_alloc_scratch(db, &scratch);
        gbps = run_overlap(db, scratch, corpus, len, chunks[i], w, &m);
        /* Every chunk re-scans the carried window, so small chunks pay most. */
        printf("  %-10zu %10.2f %11.1f%%\n", chunks[i], gbps,
               100.0 * (double)w / (double)chunks[i]);
        hs_free_scratch(scratch);
        hs_free_database(db);
    }
    patset_free(&p);
}

static void compare_modes(const char *corpus, size_t len, size_t chunk,
                          int cls, unsigned n)
{
    struct patset p;
    hs_database_t *bdb, *sdb;
    hs_scratch_t *bs = NULL, *ss = NULL;
    struct mctx m1 = { 0, 0, 0 }, m2 = { 0, 0, 0 };
    unsigned w = 0, unb = 0;
    size_t stream_sz = 0;
    double g_ov, g_st;

    patset_synth(&p, cls, n);
    if (overlap_width(&p, &w, &unb) < 0 || unb) {
        patset_free(&p);
        return;
    }
    bdb = compile(&p, HS_MODE_BLOCK);
    sdb = compile(&p, HS_MODE_STREAM);
    if (!bdb || !sdb) {
        patset_free(&p);
        return;
    }
    hs_alloc_scratch(bdb, &bs);
    hs_alloc_scratch(sdb, &ss);
    hs_stream_size(sdb, &stream_sz);

    g_ov = run_overlap(bdb, bs, corpus, len, chunk, w, &m1);
    g_st = run_stream(sdb, ss, corpus, len, chunk, &m2);

    printf("\noverlap versus streaming, %s x%u, %zu-byte chunks\n",
           class_name[cls], n, chunk);
    printf("  %-10s %10s %14s %18s\n",
           "mode", "GB/s", "bytes/stream", "at 1M sessions x2");
    printf("  %-10s %10.2f %14u %15.2f GB\n",
           "overlap", g_ov, w, 2.0 * w * 1e6 / 1e9);
    printf("  %-10s %10.2f %14zu %15.2f GB\n",
           "stream", g_st, stream_sz, 2.0 * stream_sz * 1e6 / 1e9);
    printf("  matches: overlap %llu (+%llu duplicates suppressed), stream %llu\n",
           m1.matches, m1.suppressed, m2.matches);

    hs_free_scratch(bs);
    hs_free_scratch(ss);
    hs_free_database(bdb);
    hs_free_database(sdb);
    patset_free(&p);
}

static void sweep_density(size_t len, size_t chunk, int cls, unsigned n)
{
    static const int per_mb[] = { 0, 1, 16, 256 };
    unsigned i;
    struct patset p;
    unsigned w = 0, unb = 0;

    patset_synth(&p, cls, n);
    if (overlap_width(&p, &w, &unb) < 0 || unb) {
        patset_free(&p);
        return;
    }
    printf("\nthroughput by match density, %s x%u\n", class_name[cls], n);
    printf("  %-14s %10s %14s\n", "hits/MB", "GB/s", "matches");
    for (i = 0; i < sizeof(per_mb) / sizeof(per_mb[0]); i++) {
        char *c = corpus_make(len, per_mb[i], cls);
        hs_database_t *db = compile(&p, HS_MODE_BLOCK);
        hs_scratch_t *scratch = NULL;
        struct mctx m = { 0, 0, 0 };
        double gbps;

        if (!db) {
            free(c);
            break;
        }
        hs_alloc_scratch(db, &scratch);
        gbps = run_overlap(db, scratch, c, len, chunk, w, &m);
        printf("  %-14d %10.2f %14llu\n", per_mb[i], gbps, m.matches);
        hs_free_scratch(scratch);
        hs_free_database(db);
        free(c);
    }
    patset_free(&p);
}

/* ---- main ------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    const char *patfile = NULL;
    size_t chunk = DEF_CHUNK;
    char *corpus;
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-f") && i + 1 < argc)
            patfile = argv[++i];
        else if (!strcmp(argv[i], "-c") && i + 1 < argc)
            chunk = (size_t)atoi(argv[++i]);
        else {
            fprintf(stderr, "usage: %s [-f patterns.txt] [-c chunk_bytes]\n",
                    argv[0]);
            return 2;
        }
    }

    printf("scan bench: %s, %u MB corpus, %zu-byte chunks\n",
           patfile ? patfile : "synthetic pattern sets",
           CORPUS_BYTES >> 20, chunk);

    corpus = corpus_make(CORPUS_BYTES, 0, CLASS_LITERAL);

    if (patfile) {
        struct patset p;
        hs_database_t *db;
        hs_scratch_t *scratch = NULL;
        struct mctx m = { 0, 0, 0 };
        unsigned w = 0, unb = 0;
        size_t dbsz = 0, stream_sz = 0;
        double gbps;

        if (patset_file(&p, patfile) < 0)
            die("cannot read the pattern file");
        printf("\nsupplied pattern set: %u expressions\n", p.n);
        if (overlap_width(&p, &w, &unb) < 0)
            return 1;
        if (unb) {
            printf("  %u of %u expressions have no bounded length, so no\n"
                   "  overlap window covers them: this set needs streaming.\n",
                   unb, p.n);
        } else {
            printf("  all bounded; overlap window %u bytes\n", w);
        }
        db = compile(&p, unb ? HS_MODE_STREAM : HS_MODE_BLOCK);
        if (!db)
            return 1;
        hs_alloc_scratch(db, &scratch);
        hs_database_size(db, &dbsz);
        if (unb) {
            hs_stream_size(db, &stream_sz);
            gbps = run_stream(db, scratch, corpus, CORPUS_BYTES, chunk, &m);
            note("bytes per stream", (double)stream_sz, "B");
            note("at 1M sessions x2", 2.0 * stream_sz * 1e6 / 1e9, "GB");
        } else {
            gbps = run_overlap(db, scratch, corpus, CORPUS_BYTES, chunk, w, &m);
            note("bytes per session", (double)w, "B");
            note("at 1M sessions x2", 2.0 * w * 1e6 / 1e9, "GB");
        }
        note("database size", dbsz / 1024.0, "KB");
        printf("\n");
        report("scan, clean traffic", gbps, "GB/s", GATE_SCAN_GBPS, 1);
        hs_free_scratch(scratch);
        hs_free_database(db);
        patset_free(&p);
    } else {
        sweep_class_count(corpus, CORPUS_BYTES, chunk);
        sweep_chunk(corpus, CORPUS_BYTES, CLASS_BOUNDED, 100);
        compare_modes(corpus, CORPUS_BYTES, chunk, CLASS_BOUNDED, 100);
        sweep_density(CORPUS_BYTES, chunk, CLASS_LITERAL, 100);

        {
            /* Headline: the mix a DLP set actually looks like, clean traffic. */
            struct patset p;
            hs_database_t *db;
            hs_scratch_t *scratch = NULL;
            struct mctx m = { 0, 0, 0 };
            unsigned w = 0, unb = 0;
            double gbps;

            patset_synth(&p, CLASS_BOUNDED, 100);
            overlap_width(&p, &w, &unb);
            db = compile(&p, HS_MODE_BLOCK);
            if (db) {
                hs_alloc_scratch(db, &scratch);
                gbps = run_overlap(db, scratch, corpus, CORPUS_BYTES, chunk,
                                   w, &m);
                printf("\nbudget check, 100 bounded patterns, clean traffic\n");
                report("scan per core", gbps, "GB/s", GATE_SCAN_GBPS, 1);
                note("cores for 70 Gbps", 8.75 / gbps, "cores");
                hs_free_scratch(scratch);
                hs_free_database(db);
            }
            patset_free(&p);
        }
    }

    free(corpus);
    printf("\n%s\n", g_failures ? "some gates FAILED" : "all gates passed");
    return g_failures ? 1 : 0;
}
