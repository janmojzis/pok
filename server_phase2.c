#include "packet.h"
#include "byte.h"
#include "log.h"
#include "nk.h"
#include "mc.h"
#include "server.h"

long long server_phase2(unsigned char *packet, long long packetlen) {

    /*
    query2:
    PIECES x COOKIEBLOCKBYTES encrypted box
    - PIECES x COOKIEBLOCKBYTES
    */
    struct stack {
        unsigned char nonce[mc_proto_NONCEBYTES];
        unsigned char cookienonce[mc_proto_NONCEBYTES];
        unsigned char key123[packet_KEYBYTES];
        unsigned char eseed[packet_KEYBYTES];
        unsigned char cookiekey[packet_KEYBYTES];
        unsigned char e[mc_mctiny_EBYTESMAX];
        unsigned char cookie1[mc_mctiny_VMAX][mc_mctiny_COLBLOCKSMAX]
                             [mc_mctiny_COOKIEBLOCKBYTESMAX];
        unsigned char synd1[mc_mctiny_YBYTESMAX];
        unsigned char synd2[mc_mctiny_PIECEBYTESMAX];
        struct mc mc;
    } stack;
    long long ret = -1;
    unsigned int nonce0, nonce1;
    long long piecepos, rowpos;
    long long i, j;

    /* extract nonce */
    byte_copy(stack.nonce, mc_proto_NONCEBYTES,
              packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES);
    byte_copy(stack.cookienonce, mc_proto_NONCEBYTES, stack.nonce);

    /* select mctiny variant */
    if (!mc_fromid(&stack.mc, stack.nonce[sizeof stack.nonce - 3])) {
        log_w1("unable to parse mctiny variant from the query2 nonce");
        goto cleanup;
    }

    /* check packet length */
    if (stack.mc.mctiny.query2bytes != packetlen) {
        log_w1("bad query2 length");
        goto cleanup;
    }

    /* check nonce */
    nonce0 = stack.nonce[sizeof stack.nonce - 2];
    nonce1 = stack.nonce[sizeof stack.nonce - 1];
    piecepos = 127 & (nonce0 / 2);
    if (piecepos >= stack.mc.mctiny.pieces) {
        log_w1("bad query2 nonce");
        goto cleanup;
    }
    if (nonce0 != 2 * piecepos) {
        log_w1("bad query2 nonce");
        goto cleanup;
    }
    if (nonce1 != 64 + 32) {
        log_w1("bad query2 nonce");
        goto cleanup;
    }

    /* derive key123, essed, cookiekey */
    nk_derivekeys(stack.key123, stack.eseed, stack.cookiekey, stack.nonce);

    /* decrypt query2 */
    packet_incoming(packet + mc_proto_HEADERBYTES,
                    packetlen - mc_proto_HEADERBYTES);
    if (packet_decrypt(stack.nonce, stack.key123) != 0) {
        log_w1("unable to decrypt query2 packet");
        goto cleanup;
    }
    for (j = stack.mc.mctiny.v - 1; j >= 0; --j)
        for (i = stack.mc.mctiny.colblocks - 1; i >= 0; --i)
            packet_extract(stack.cookie1[j][i],
                           stack.mc.mctiny.cookieblockbytes);

    /* derive e from eseed */
    mc_mctiny_seed2e(&stack.mc, stack.e, stack.eseed);

    /* synd2 */
    mc_mctiny_pieceinit(&stack.mc, stack.synd2, stack.e, piecepos);
    for (j = 0; j < stack.mc.mctiny.v; ++j) {
        rowpos = stack.mc.mctiny.v * piecepos + j;
        if (rowpos >= stack.mc.mctiny.rowblocks) continue;
        for (i = 0; i < stack.mc.mctiny.colblocks; ++i) {
            packet_incoming(stack.cookie1[j][i],
                            stack.mc.mctiny.cookieblockbytes);
            stack.cookienonce[sizeof stack.cookienonce - 2] = rowpos * 2 + 1;
            stack.cookienonce[sizeof stack.cookienonce - 1] = 64 + i;
            if (packet_decrypt(stack.cookienonce, stack.cookiekey) != 0) {
                log_w1("unable to decrypt cookie1 from query2");
                goto cleanup;
            }
            packet_extract(stack.synd1, stack.mc.mctiny.ybytes);
            if (!packet_isok()) {
                log_w1("unable to parse Yblock from query2");
                goto cleanup;
            }
            mc_mctiny_pieceabsorb(&stack.mc, stack.synd2, stack.synd1, j);
        }
    }

    /*
    reply2:
    PIECEBYTES encrypted box
    - PIECEBYTES synd2
    */

    stack.nonce[sizeof stack.nonce - 2] += 1; /* bump nonce */

    /* reply2 */
    packet_clear();
    packet_append(stack.synd2, stack.mc.mctiny.piecebytes);
    packet_encrypt(stack.nonce, stack.key123);
    byte_copy(packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES,
              mc_proto_NONCEBYTES, stack.nonce);
    packet_outgoing(packet + mc_proto_HEADERBYTES,
                    stack.mc.mctiny.reply2bytes - mc_proto_HEADERBYTES);

    ret = stack.mc.mctiny.reply2bytes;
cleanup:
    byte_zero(&stack, sizeof stack);
    return ret;
}
