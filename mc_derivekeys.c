#include "crypto_stream_xsalsa20.h"
#include "byte.h"
#include "mc.h"

void mc_derivekeys(unsigned char *k1, unsigned char *k2,
                   const unsigned char *k) {

    unsigned char keys[2 * mc_KEYBYTES];
    unsigned char n[crypto_stream_xsalsa20_NONCEBYTES] = {0};

    crypto_stream_xsalsa20(keys, sizeof keys, n, k);
    if (k1) byte_copy(k1, mc_KEYBYTES, keys + 0 * mc_KEYBYTES);
    if (k2) byte_copy(k2, mc_KEYBYTES, keys + 1 * mc_KEYBYTES);
    byte_zero(keys, sizeof keys);
}
