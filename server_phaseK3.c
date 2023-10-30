#include "packet.h"
#include "byte.h"
#include "log.h"
#include "nk.h"
#include "mc.h"
#include "server.h"

long long server_phaseK3(unsigned char *packet, long long p3piecepos,
                         int flagauth) {

    /*
    query3:
    PIECES x COOKIEBLOCKBYTES encrypted box
    - PIECES x COOKIEBLOCKBYTES
    */
    struct stack {
        unsigned char nonce[mc_NONCEBYTES];
        unsigned char cookienonce[mc_NONCEBYTES];
        unsigned char key1234query[packet_KEYBYTES];
        unsigned char key1234reply[packet_KEYBYTES];
        unsigned char e0seed[packet_KEYBYTES];
        unsigned char e1seed[packet_KEYBYTES];
        unsigned char cookiekey[packet_KEYBYTES];
        unsigned char cookie2[mc_mctiny_PIECES][mc_mctiny_COOKIE2BLOCKBYTES];
        unsigned char synd2[mc_mctiny_PIECES][mc_mctiny_PIECEBYTES];
        unsigned char hash2[mc_HASHBYTES * mc_mctiny_PIECES];
        unsigned char hash3[mc_HASHBYTES];
        unsigned char cookie3[mc_mctiny_COOKIE3BLOCKBYTES];
    } stack;
    long long ret = -1;
    long long i;

    /* extract nonce */
    byte_copy(stack.nonce, mc_NONCEBYTES,
              packet + mc_MAGICBYTES + mc_EXTENSIONBYTES);
    byte_copy(stack.cookienonce, mc_NONCEBYTES, stack.nonce);

    /* derive key1234query, key1234reply, e0, e1, cookiekey */
    nk_derivekeys(stack.key1234query, stack.key1234reply, stack.e0seed,
                  stack.e1seed, stack.cookiekey, stack.nonce);

    /* decrypt query3 */
    packet_incoming(packet + mc_HEADERBYTES,
                    mc_mctiny_QUERYK3BYTES - mc_HEADERBYTES);
    if (packet_decrypt(stack.nonce, stack.key1234query) != 0) {
        log_w1("unable to decrypt query3 packet");
        goto cleanup;
    }

    /* extract cookies2 */
    for (i = mc_mctiny_P3BLOCKS - 1; i >= 0; --i) {
        packet_extract(stack.cookie2[i], mc_mctiny_COOKIE2BLOCKBYTES);
    }
    if (!packet_isok()) {
        log_w1("unable to parse query3 packet");
        goto cleanup;
    }

    byte_zero(stack.hash2, sizeof stack.hash2);
    for (i = 0; i < mc_mctiny_P3BLOCKS; ++i) {
        /* extract synd2, hash2 */
        long long piecepos = p3piecepos * mc_mctiny_P3BLOCKS + i;
        if (piecepos < mc_mctiny_PIECES) {
            packet_incoming(stack.cookie2[i], mc_mctiny_COOKIE2BLOCKBYTES);
            mc_Levpos_store(stack.cookienonce + mc_NONCEBYTES - 2, 2, piecepos,
                            flagauth);
            if (packet_decrypt(stack.cookienonce, stack.cookiekey) != 0) {
                log_w2("unable to decrypt cookie2 from query3/",
                       log_num0(p3piecepos, 3));
                goto cleanup;
            }
            packet_extract(stack.synd2[i], mc_mctiny_PIECEBYTES);
            packet_extract(stack.hash2 + i * mc_HASHBYTES, mc_HASHBYTES);
            if (!packet_isok()) {
                log_w2("unable to parse cookie2 from query3/",
                       log_num0(p3piecepos, 3));
                goto cleanup;
            }
        }
        else { /* blank */
        }
    }
    mceliece_xof_shake256(stack.hash3, mc_HASHBYTES, stack.hash2,
                          mc_mctiny_P3BLOCKS * mc_HASHBYTES);

    /*
    reply3:
    */

    /* cookie3 */
    packet_clear();
    packet_append(stack.hash3, mc_HASHBYTES);
    for (i = 0; i < mc_mctiny_P3BLOCKS; ++i) {
        packet_append(stack.synd2[i], mc_mctiny_PIECEBYTES);
    }
    packet_encrypt(stack.nonce, stack.cookiekey);
    packet_outgoing(stack.cookie3, mc_mctiny_COOKIE3BLOCKBYTES);

    /* reply3 */
    packet_clear();
    packet_append(stack.cookie3, mc_mctiny_COOKIE3BLOCKBYTES);
    packet_encrypt(stack.nonce, stack.key1234reply);
    byte_copy(packet + mc_MAGICBYTES + mc_EXTENSIONBYTES, mc_NONCEBYTES,
              stack.nonce);
    byte_copy(packet, mc_MAGICBYTES, mc_MAGICREPLYK);
    packet_outgoing(packet + mc_HEADERBYTES,
                    mc_mctiny_REPLYK3BYTES - mc_HEADERBYTES);

    ret = mc_mctiny_REPLYK3BYTES;
cleanup:
    byte_zero(&stack, sizeof stack);
    return ret;
}
