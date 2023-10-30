#include "packet.h"
#include "byte.h"
#include "log.h"
#include "nk.h"
#include "mc.h"
#include "server.h"

long long server_phaseK2(unsigned char *packet, long long piecepos,
                         int flagauth) {

    /*
    query2:
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
        unsigned char e[mc_mctiny_EBYTES];
        unsigned char cookie1[mc_mctiny_V][mc_mctiny_COLBLOCKS]
                             [mc_mctiny_COOKIE1BLOCKBYTES];
        unsigned char synd1[mc_mctiny_YBYTES];
        unsigned char synd2[mc_mctiny_PIECEBYTES];
        unsigned char hash1[mc_HASHBYTES * mc_mctiny_V * mc_mctiny_COLBLOCKS];
        unsigned char hash2[mc_HASHBYTES];
        unsigned char cookie2[mc_mctiny_COOKIE2BLOCKBYTES];
    } stack;
    long long ret = -1;
    long long rowpos;
    long long i, j, k = 0;

    /* extract nonce */
    byte_copy(stack.nonce, mc_NONCEBYTES,
              packet + mc_MAGICBYTES + mc_EXTENSIONBYTES);
    byte_copy(stack.cookienonce, mc_NONCEBYTES, stack.nonce);

    /* derive key1234query, key1234reply, e0, e1, cookiekey */
    nk_derivekeys(stack.key1234query, stack.key1234reply, stack.e0seed,
                  stack.e1seed, stack.cookiekey, stack.nonce);

    /* decrypt query2 */
    packet_incoming(packet + mc_HEADERBYTES,
                    mc_mctiny_QUERYK2BYTES - mc_HEADERBYTES);
    if (packet_decrypt(stack.nonce, stack.key1234query) != 0) {
        log_w1("unable to decrypt query2 packet");
        goto cleanup;
    }
    for (j = mc_mctiny_V - 1; j >= 0; --j)
        for (i = mc_mctiny_COLBLOCKS - 1; i >= 0; --i)
            packet_extract(stack.cookie1[j][i], mc_mctiny_COOKIE1BLOCKBYTES);
    if (!packet_isok()) {
        log_w1("unable to parse query2 packet");
        goto cleanup;
    }

    /* derive e from eseed */
    if (flagauth) { mc_mctiny_seed2e(stack.e, stack.e1seed); }
    else { mc_mctiny_seed2e(stack.e, stack.e0seed); }

    /* synd2 */
    mc_mctiny_pieceinit(stack.synd2, stack.e, piecepos);
    byte_zero(stack.hash1, sizeof stack.hash1);
    for (j = 0; j < mc_mctiny_V; ++j) {
        rowpos = mc_mctiny_V * piecepos + j;
        if (rowpos >= mc_mctiny_ROWBLOCKS) continue;
        for (i = 0; i < mc_mctiny_COLBLOCKS; ++i) {
            packet_incoming(stack.cookie1[j][i], mc_mctiny_COOKIE1BLOCKBYTES);
            mc_Levpos_store(stack.cookienonce + mc_NONCEBYTES - 2, 1,
                            rowpos * mc_mctiny_COLBLOCKS + i, flagauth);
            if (packet_decrypt(stack.cookienonce, stack.cookiekey) != 0) {
                log_w1("unable to decrypt cookie1 from query2");
                goto cleanup;
            }
            packet_extract(stack.synd1, mc_mctiny_YBYTES);
            packet_extract(stack.hash1 + k, mc_HASHBYTES);
            k += mc_HASHBYTES;
            if (!packet_isok()) {
                log_w1("unable to parse cookie1 from query2");
                goto cleanup;
            }
            mc_mctiny_pieceabsorb(stack.synd2, stack.synd1, j);
        }
    }

    /* hash2, l3blockbytes */
    mceliece_xof_shake256(stack.hash2, mc_HASHBYTES, stack.hash1,
                          mc_pktree_L3BLOCKBYTES);

    /*
    reply2:
    - COOKIE2BLOCKBYTES cookie2
    - PIECEBYTES synd2
    */

    /* cookie2 */
    packet_clear();
    packet_append(stack.hash2, mc_HASHBYTES);
    packet_append(stack.synd2, mc_mctiny_PIECEBYTES);
    packet_encrypt(stack.nonce, stack.cookiekey);
    packet_outgoing(stack.cookie2, mc_mctiny_COOKIE2BLOCKBYTES);

    /* reply2 */
    packet_clear();
    packet_append(stack.cookie2, mc_mctiny_COOKIE2BLOCKBYTES);
    packet_encrypt(stack.nonce, stack.key1234reply);
    byte_copy(packet + mc_MAGICBYTES + mc_EXTENSIONBYTES, mc_NONCEBYTES,
              stack.nonce);
    byte_copy(packet, mc_MAGICBYTES, mc_MAGICREPLYK);
    packet_outgoing(packet + mc_HEADERBYTES,
                    mc_mctiny_REPLYK2BYTES - mc_HEADERBYTES);

    ret = mc_mctiny_REPLYK2BYTES;
cleanup:
    byte_zero(&stack, sizeof stack);
    return ret;
}
