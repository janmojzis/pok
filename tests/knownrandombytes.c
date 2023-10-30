#include <string.h>
#include <errno.h>
#include <randombytes.h>
#include "crypto_stream_chacha20.h"
#include "log.h"

#define KEYBYTES crypto_stream_chacha20_KEYBYTES
#define OUTPUTBYTES 736

static unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];
static unsigned char g[KEYBYTES];
static unsigned char r[OUTPUTBYTES];
static unsigned long long pos = OUTPUTBYTES;

int crypto_rng(unsigned char *r,      /* random output */
               unsigned char *n,      /* new key */
               const unsigned char *g /* old key */
) {
    unsigned char x[KEYBYTES + OUTPUTBYTES];
    crypto_stream_chacha20(x, sizeof x, nonce, g);
    memcpy(n, x, KEYBYTES);
    memcpy(r, x + KEYBYTES, OUTPUTBYTES);
    return 0;
}

void randombytes(void *xv, long long xlen) {

    unsigned char *x = xv;

    errno = 0;
    log_w1(
        "knownrandombytes() is only for testing not for cryptographic use !!!");

    while (xlen > 0) {
        if (pos == OUTPUTBYTES) {
            crypto_rng(r, g, g);
            pos = 0;
        }
        *x++ = r[pos];
        xlen -= 1;
        r[pos++] = 0;
    }
}
