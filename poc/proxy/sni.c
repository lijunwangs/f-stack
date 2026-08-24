/* TLS ClientHello SNI extraction. No OpenSSL: this runs before any SSL
 * object exists, on bytes we have merely buffered. */

#include <string.h>

#include "proxy.h"

#define TLS_HANDSHAKE       22
#define HS_CLIENT_HELLO     1
#define EXT_SERVER_NAME     0
#define SNI_HOST_NAME       0

static uint32_t be16(const uint8_t *p) { return ((uint32_t)p[0] << 8) | p[1]; }

int sni_parse(const uint8_t *buf, size_t len, char *sni, size_t sni_cap)
{
    size_t pos, end, ext_end, rec_len, hs_len;

    if (len < 5)
        return 0;
    if (buf[0] != TLS_HANDSHAKE)
        return -1;

    rec_len = be16(buf + 3);
    if (rec_len == 0 || rec_len > CH_BUF_MAX)
        return -1;
    if (len < 5 + rec_len)
        return 0;

    /* handshake header: type(1) length(3) */
    if (buf[5] != HS_CLIENT_HELLO)
        return -1;
    hs_len = ((size_t)buf[6] << 16) | ((size_t)buf[7] << 8) | buf[8];
    pos = 9;
    end = pos + hs_len;
    if (end > 5 + rec_len || end > len)
        return 0;

    pos += 2 + 32;                          /* client_version + random */
    if (pos >= end)
        return -1;
    pos += 1 + buf[pos];                    /* legacy_session_id */
    if (pos + 2 > end)
        return -1;
    pos += 2 + be16(buf + pos);             /* cipher_suites */
    if (pos + 1 > end)
        return -1;
    pos += 1 + buf[pos];                    /* compression_methods */
    if (pos + 2 > end)
        return -1;

    ext_end = pos + 2 + be16(buf + pos);
    pos += 2;
    if (ext_end > end)
        return -1;

    while (pos + 4 <= ext_end) {
        uint32_t etype = be16(buf + pos);
        uint32_t elen = be16(buf + pos + 2);
        const uint8_t *e = buf + pos + 4;

        if (pos + 4 + elen > ext_end)
            return -1;

        if (etype == EXT_SERVER_NAME && elen >= 5) {
            /* server_name_list: list_len(2) then type(1) len(2) host */
            uint32_t nlen = be16(e + 3);

            if (e[2] == SNI_HOST_NAME && nlen > 0 && nlen + 5 <= elen &&
                nlen < sni_cap) {
                memcpy(sni, e + 5, nlen);
                sni[nlen] = '\0';
                return 1;
            }
            return -1;
        }
        pos += 4 + elen;
    }
    return -1;      /* well-formed ClientHello, but no SNI to key policy on */
}
