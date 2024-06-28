#include <randombytes.h>
#include "crypto_stream_xsalsa20.h"
#include "crypto_block.h"
#include "uint64_pack.h"
#include "byte.h"
#include "packet.h"
#include "nk.h"

#if crypto_stream_xsalsa20_NONCEBYTES != packet_NONCEBYTES
#error "crypto_stream_xsalsa20_NONCEBYTES != packet_NONCEBYTES"
#endif

static int initialized = 0;
static uint64_t counter = (uint64_t) -1;
static unsigned char counterkey[crypto_block_KEYBYTES];
static unsigned char keyid = 0;
#define MASK (nk_KEYS - 1)
static unsigned char key[nk_KEYS][crypto_stream_xsalsa20_KEYBYTES];

void nk_cleanup(void) {
    keyid = 0;
    randombytes((unsigned char *) key, sizeof key);
}

void nk_next(void) {

    if (!initialized) {
        nk_cleanup();
        initialized = 1;
    }

    keyid = (keyid + 1) % nk_KEYS;
    randombytes(key[keyid], sizeof(key[keyid]));
}

void nk_nonce(unsigned char *x) {

    if (!initialized) {
        nk_cleanup();
        initialized = 1;
    }

    /* encrypted 8B counter + 8B random */
    if (!++counter) { randombytes(counterkey, sizeof counterkey); }
    uint64_pack(x + 0, counter);
    randombytes(x + 8, 8);
    crypto_block(x, x, counterkey);

    /* 5B ... random */
    randombytes(x + 16, 5);

    /* insert keyid into the nonce */
    x[packet_NONCEBYTES - 3] &= MASK ^ 0xff;
    x[packet_NONCEBYTES - 3] |= keyid;
}

int nk_keyid(unsigned char *nonce) {
    return nonce[packet_NONCEBYTES - 3] & MASK;
}

void nk_derivekeys(unsigned char *key123, unsigned char *eseed,
                   unsigned char *cookiekey, unsigned char *nonce) {
    unsigned char seeds[3 * packet_KEYBYTES];
    unsigned char n[packet_NONCEBYTES];
    unsigned char *k = key[nk_keyid(nonce)];

    byte_copy(n, packet_NONCEBYTES - 2, nonce);
    n[packet_NONCEBYTES - 2] = 0;
    n[packet_NONCEBYTES - 1] = 0;

    crypto_stream_xsalsa20(seeds, sizeof seeds, n, k);

    byte_copy(key123, packet_KEYBYTES, seeds);
    byte_copy(eseed, packet_KEYBYTES, seeds + packet_KEYBYTES);
    byte_copy(cookiekey, packet_KEYBYTES, seeds + 2 * packet_KEYBYTES);
    byte_zero(seeds, sizeof seeds);
}

#ifdef TEST
void nk_nonce_decrypt(unsigned char *x) {
    crypto_block_decrypt(x, x, counterkey);
}
#endif
