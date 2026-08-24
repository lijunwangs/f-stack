/* POC inspection stub: a single literal pattern over the plaintext stream.
 * Stands in for the streaming Vectorscan engine; the point of the POC is that
 * plaintext reaches this function at all, and what it costs to get here. */

#include <string.h>

#include "proxy.h"

static char pat[64];
static size_t pat_len;
static unsigned long stat_bytes, stat_hits;

int scan_init(const char *pattern)
{
    if (!pattern || !*pattern)
        return -1;
    pat_len = strlen(pattern);
    if (pat_len >= sizeof(pat))
        return -1;
    memcpy(pat, pattern, pat_len + 1);
    return 0;
}

int scan_buf(const uint8_t *buf, size_t len)
{
    size_t i;

    stat_bytes += len;
    if (pat_len == 0 || len < pat_len)
        return 0;

    /*
     * Deliberately naive: a real engine keeps streaming state across buffers
     * so a match spanning a boundary is still caught. Noted as a POC gap.
     */
    for (i = 0; i + pat_len <= len; i++) {
        if (buf[i] == (uint8_t)pat[0] && !memcmp(buf + i, pat, pat_len)) {
            stat_hits++;
            return 1;
        }
    }
    return 0;
}

void scan_stats(unsigned long *bytes, unsigned long *hits)
{
    if (bytes)
        *bytes = stat_bytes;
    if (hits)
        *hits = stat_hits;
}
