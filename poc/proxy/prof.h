/*
 * Cycle accounting for the relay's inner loop.
 *
 * perf is a poor instrument here: sampling a busy-polling process dragged
 * throughput from tens of MB/s to 1.3, and the profile that came back
 * described a loop spinning with no work rather than the work itself. These
 * counters cost a pair of rdtsc reads around calls that already do real work,
 * and they sit in code shared by both backends, so the F-Stack and kernel
 * builds report the same buckets and can be compared line for line.
 */

#ifndef POC_PROF_H
#define POC_PROF_H

#include <stdint.h>
#include <stddef.h>

enum {
    P_EVWAIT = 0,   /* waiting for readiness */
    P_EVSET,        /* changing what a leg is registered for */
    P_SOCKRD,       /* socket read */
    P_SOCKWR,       /* socket write */
    P_SSLRD,        /* decrypt */
    P_SSLWR,        /* encrypt */
    P_SCAN,         /* inspection */
    P_HANDSHAKE,    /* TLS handshake steps */
    P_N
};

extern uint64_t prof_cyc[P_N];
extern uint64_t prof_cnt[P_N];
extern const char *prof_name[P_N];
/* Readiness events actually returned, against the number of times we asked. */
extern uint64_t prof_events;
extern uint64_t prof_relay_calls;
extern uint64_t prof_relay_bytes;
extern uint64_t prof_rd_calls, prof_rd_bytes, prof_rd_done;
extern uint64_t prof_queued, prof_queued_n;

static inline uint64_t prof_tsc(void)
{
#if defined(__x86_64__) || defined(__i386__)
    return __builtin_ia32_rdtsc();
#else
    return 0;
#endif
}

/* Time an expression and keep its value. */
#define PROF_V(slot, lval, expr)                    \
    do {                                            \
        uint64_t _p0 = prof_tsc();                  \
        (lval) = (expr);                            \
        prof_cyc[slot] += prof_tsc() - _p0;         \
        prof_cnt[slot]++;                           \
    } while (0)

/* Time a call whose value is not needed. */
#define PROF_S(slot, expr)                          \
    do {                                            \
        uint64_t _p0 = prof_tsc();                  \
        (expr);                                     \
        prof_cyc[slot] += prof_tsc() - _p0;         \
        prof_cnt[slot]++;                           \
    } while (0)

/*
 * Render the buckets as a share of the interval and reset them. Shares are of
 * wall time, not of each other, so what is missing from the total is the time
 * the loop spent somewhere none of these buckets covers.
 */
void prof_report(char *out, size_t len, uint64_t interval_cycles);

#endif /* POC_PROF_H */
