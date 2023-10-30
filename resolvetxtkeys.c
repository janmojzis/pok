#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "parsehex.h"
#include "log.h"
#include "byte.h"
#include "e.h"
#include "randommod.h"
#include "resolvetxtkeys.h"

static void swap(unsigned char *x, unsigned char *y) {

    char t[32];

    byte_copy(t, 32, x);
    byte_copy(x, 32, y);
    byte_copy(y, 32, t);
}

static void randomize(unsigned char *s, long long nn) {

    long long i, n = nn;

    if (nn < 0) return;

    n >>= 5;
    while (n > 1) {
        i = randommod(n);
        --n;
        swap(s + 32 * i, s + 32 * n);
    }
}

static long long dns_packet_copy(const unsigned char *buf, long long len,
                                 long long pos, unsigned char *out,
                                 long long outlen) {

    while (outlen > 0) {
        if (pos >= len) {
            errno = EPROTO;
            return 0;
        }
        *out = buf[pos++];
        ++out;
        --outlen;
    }
    return pos;
}

static long long dns_packet_skipname(const unsigned char *buf, long long len,
                                     long long pos) {

    unsigned char ch;

    for (;;) {
        if (pos >= len) break;
        ch = buf[pos++];
        if (ch >= 192) return pos + 1;
        if (ch >= 64) break;
        if (!ch) return pos;
        pos += ch;
    }

    errno = EPROTO;
    return 0;
}

long long resolvetxtkeys(unsigned char *out, long long outsize,
                         const char *domain) {

    unsigned char buf[4096];
    long long len, i, txtlen, pos = 0;
    unsigned char misc[32];
    unsigned char tmp[256];
    long long outlen = 0;
    unsigned long long tmplen = 0;
    unsigned int numanswers, datalen;
    unsigned char ch;

    /* send query */
    len = res_query(domain, ns_c_in, ns_t_txt, buf, sizeof buf);
    if (len < 0) return len;

    /* parse headers */
    pos = dns_packet_copy(buf, len, pos, misc, 12);
    if (!pos) goto proto;
    numanswers = ns_get16(misc + 6);
    pos = dns_packet_skipname(buf, len, pos);
    if (!pos) goto proto;
    pos += 4;

    /* parse records */
    /* PoKv0dD=0000000000000000000000000000000000000000000000000000000000000000
     */
    while (numanswers--) {
        pos = dns_packet_skipname(buf, len, pos);
        if (!pos) goto proto;
        pos = dns_packet_copy(buf, len, pos, misc, 10);
        if (!pos) goto proto;
        datalen = ns_get16(misc + 8);
        if (pos + datalen > len) goto proto;
        if ((ns_get16(misc) == ns_t_txt) && (ns_get16(misc + 2) == ns_c_in)) {
            txtlen = 0;
            tmplen = 0;
            for (i = 0; i < datalen; ++i) {
                ch = buf[pos + i];
                if (!txtlen) {
                    txtlen = ch;
                    tmplen = 0;
                }
                else {
                    --txtlen;
                    if (tmplen >= sizeof tmp) break;
                    tmp[tmplen++] = ch;
                }
            }
            if (tmplen == 72) {
                tmp[tmplen++] = 0;
                if (byte_isequal(tmp, 8, "PoKv0dD=")) {
                    if (parsehex(misc, 32, (char *) tmp + 8)) {
                        if (outlen + 32 <= outsize) {
                            byte_copy(out + outlen, 32, misc);
                            outlen += 32;
                        }
                    }
                }
            }
        }

        pos += datalen;
    }

    randomize(out, outlen);
    return outlen;

proto:
    errno = EPROTO;
    return -1;
}
