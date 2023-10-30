#include <mceliece.h>
#include "packet.h"
#include "byte.h"
#include "log.h"
#include "nk.h"
#include "mc.h"
#include "server.h"

long long server_phaseK4(unsigned char *packet) {

    /*
    query4:
    */

    struct stack {
        unsigned char nonce[mc_NONCEBYTES];
        unsigned char cookienonce[mc_NONCEBYTES];
        unsigned char cookiekey[packet_KEYBYTES];
        unsigned char key1234query[packet_KEYBYTES];
        unsigned char key1234reply[packet_KEYBYTES];
        unsigned char e0seed[packet_KEYBYTES];
        unsigned char e1seed[packet_KEYBYTES];
        unsigned char e[mc_mctiny_EBYTES];
        unsigned char synd4[2][mc_mctiny_COLBYTES];
        unsigned char synd2[2][mc_mctiny_PIECES][mc_mctiny_PIECEBYTES];
        unsigned char blanksynd2[mc_mctiny_PIECEBYTES];
        unsigned char ciphertext[2][mc_CIPHERTEXTBYTES];
        unsigned char key9[2 * packet_KEYBYTES];
        unsigned char cookie9[mc_mctiny_COOKIE9BYTES];
        unsigned char cookie3[2][mc_mctiny_P3PIECES]
                             [mc_mctiny_COOKIE3BLOCKBYTES];
        unsigned char hash3[2][mc_HASHBYTES * mc_mctiny_P3PIECES];
        unsigned char hash4[2][mc_HASHBYTES];
    } stack;
    long long ret = -1;
    long long i, j;
    int flagauth;

    /* extract nonce */
    byte_copy(stack.nonce, mc_NONCEBYTES,
              packet + mc_MAGICBYTES + mc_EXTENSIONBYTES);
    byte_copy(stack.cookienonce, mc_NONCEBYTES, stack.nonce);

    /* derive key1234query, key1234reply, e0, e1, cookiekey */
    nk_derivekeys(stack.key1234query, stack.key1234reply, stack.e0seed,
                  stack.e1seed, stack.cookiekey, stack.nonce);

    /* decrypt query4 */
    packet_incoming(packet + mc_HEADERBYTES,
                    mc_mctiny_QUERYK4BYTES - mc_HEADERBYTES);
    if (packet_decrypt(stack.nonce, stack.key1234query) != 0) {
        log_w1("unable to decrypt query4 packet");
        goto cleanup;
    }
    /* extract cookies3 */
    for (flagauth = 1; flagauth >= 0; --flagauth) {
        for (i = mc_mctiny_P3PIECES - 1; i >= 0; --i) {
            packet_extract(stack.cookie3[flagauth][i],
                           mc_mctiny_COOKIE3BLOCKBYTES);
        }
    }
    if (!packet_isok()) {
        log_w1("unable to parse query4 packet");
        goto cleanup;
    }

    for (flagauth = 0; flagauth < 2; ++flagauth) {
        /* extract synd2 + hash3 */
        for (i = 0; i < mc_mctiny_P3PIECES; ++i) {
            packet_incoming(stack.cookie3[flagauth][i],
                            mc_mctiny_COOKIE3BLOCKBYTES);
            mc_Levpos_store(stack.cookienonce + mc_NONCEBYTES - 2, 3, i,
                            flagauth);
            if (packet_decrypt(stack.cookienonce, stack.cookiekey) != 0) {
                log_w1("unable to decrypt cookie3 from query4");
                goto cleanup;
            }
            for (j = mc_mctiny_P3BLOCKS - 1; j >= 0; --j) {
                long long piecepos = i * mc_mctiny_P3BLOCKS + j;
                if (piecepos < mc_mctiny_PIECES) {
                    packet_extract(stack.synd2[flagauth][piecepos],
                                   mc_mctiny_PIECEBYTES);
                }
                else { packet_extract(stack.blanksynd2, mc_mctiny_PIECEBYTES); }
            }
            packet_extract(stack.hash3[flagauth] + i * mc_HASHBYTES,
                           mc_HASHBYTES);
            if (!packet_isok()) {
                log_w1("unable to parse cookie3 from query4");
                goto cleanup;
            }
        }

        /* hash4 */
        mceliece_xof_shake256(stack.hash4[flagauth], mc_HASHBYTES,
                              stack.hash3[flagauth],
                              mc_mctiny_P3PIECES * mc_HASHBYTES);

        /* synd4 */
        mc_mctiny_mergepieces(stack.synd4[flagauth], stack.synd2[flagauth]);

        /* derive e from eseed */
        if (flagauth) { mc_mctiny_seed2e(stack.e, stack.e1seed); }
        else { mc_mctiny_seed2e(stack.e, stack.e0seed); }

        mc_mctiny_finalize(stack.ciphertext[flagauth],
                           stack.key9 + flagauth * packet_KEYBYTES,
                           stack.synd4[flagauth], stack.e);
    }

    /* key9 */
    mceliece_xof_shake256(stack.key9, 2 * packet_KEYBYTES, stack.key9,
                          2 * packet_KEYBYTES);

    /*
    reply4:
    */

    /* cookie9 */
    packet_clear();
    packet_append(stack.key9, packet_KEYBYTES);
    packet_append(stack.hash4[1], mc_HASHBYTES);
    packet_encrypt(stack.nonce, stack.cookiekey);
    packet_append(stack.nonce, mc_NONCEBYTES);
    packet_outgoing(stack.cookie9, mc_mctiny_COOKIE9BYTES);

    /* reply4 */
    packet_clear();
    packet_append(stack.cookie9, mc_mctiny_COOKIE9BYTES);
    packet_append(stack.ciphertext[0], mc_CIPHERTEXTBYTES);
    packet_append(stack.ciphertext[1], mc_CIPHERTEXTBYTES);
    packet_encrypt(stack.nonce, stack.key1234reply);
    byte_copy(packet, mc_MAGICBYTES, mc_MAGICREPLYK);
    byte_copy(packet + mc_MAGICBYTES + mc_EXTENSIONBYTES, mc_NONCEBYTES,
              stack.nonce);
    packet_outgoing(packet + mc_HEADERBYTES,
                    mc_mctiny_REPLYK4BYTES - mc_HEADERBYTES);

    ret = mc_mctiny_REPLYK4BYTES;
    log_d2("key-exchange: authorization public-key hash: ",
           log_hex(stack.hash4[1], mc_HASHBYTES));
    log_d2("key-exchange: one-time (fs) public-key hash: ",
           log_hex(stack.hash4[0], mc_HASHBYTES));
    log_d2("key-exchange: session secret-key identifier: ",
           log_hex(stack.key9 + packet_KEYBYTES, mc_HASHBYTES));
cleanup:
    byte_zero(&stack, sizeof stack);
    return ret;
}
