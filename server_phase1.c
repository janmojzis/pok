#include "packet.h"
#include "byte.h"
#include "log.h"
#include "nk.h"
#include "mc.h"
#include "server.h"

long long server_phase1(unsigned char *packet, long long packetlen) {

    /*
    query1:
    BLOCKBYTES encrypted box
    - BLOCKBYTES pk block
    */

    struct stack {
        unsigned char key123[packet_KEYBYTES];
        unsigned char eseed[packet_KEYBYTES];
        unsigned char cookiekey[packet_KEYBYTES];
        unsigned char e[mc_mctiny_EBYTESMAX];
        unsigned char synd1[mc_mctiny_YBYTESMAX];
        unsigned char cookie1[mc_mctiny_COOKIEBLOCKBYTESMAX];
        unsigned char nonce[mc_proto_NONCEBYTES];
        unsigned char box[mc_mctiny_BLOCKBYTESMAX];
        struct mc mc;
    } stack;
    long long ret = -1;
    unsigned int nonce0, nonce1;
    long long rowpos, colpos;

    /* extract nonce */
    byte_copy(stack.nonce, mc_proto_NONCEBYTES,
              packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES);

    /* select mctiny variant */
    if (!mc_fromid(&stack.mc, stack.nonce[sizeof stack.nonce - 3])) {
        log_w1("unable to parse mctiny variant from the query1 nonce");
        goto cleanup;
    }

    /* check packet length */
    if (stack.mc.mctiny.query1bytes > packetlen) {
        log_w1("bad query1 length");
        goto cleanup;
    }

    /* check nonce */
    nonce0 = stack.nonce[sizeof stack.nonce - 2];
    nonce1 = stack.nonce[sizeof stack.nonce - 1];
    rowpos = 127 & (nonce0 / 2);
    colpos = 31 & nonce1;
    if (rowpos >= stack.mc.mctiny.rowblocks) {
        log_w1("bad query1 nonce");
        goto cleanup;
    }
    if (colpos >= stack.mc.mctiny.colblocks) {
        log_w1("bad query1 nonce");
        goto cleanup;
    }

    /* derive key123, essed, cookiekey */
    nk_derivekeys(stack.key123, stack.eseed, stack.cookiekey, stack.nonce);

    /* decrypt query1 */
    packet_incoming(packet + mc_proto_HEADERBYTES,
                    stack.mc.mctiny.query1bytes - mc_proto_HEADERBYTES);
    if (packet_decrypt(stack.nonce, stack.key123) != 0) {
        log_w1("unable to decrypt query1");
        goto cleanup;
    }
    packet_extract(stack.box, stack.mc.mctiny.blockbytes);
    if (!packet_isok()) {
        log_e1("unable to parse query1");
        goto cleanup;
    }

    /* derive e from eseed */
    mc_mctiny_seed2e(&stack.mc, stack.e, stack.eseed);

    /* synd1 */
    mc_mctiny_eblock2syndrome(&stack.mc, stack.synd1, stack.e, stack.box,
                              colpos);

    /*
    reply1:
    COOKIEBLOCKBYTES encrypted box
    - COOKIEBLOCKBYTES cookie1
    */

    stack.nonce[sizeof stack.nonce - 2] += 1; /* bump nonce */

    /* cookie1 */
    packet_clear();
    packet_append(stack.synd1, stack.mc.mctiny.ybytes);
    packet_encrypt(stack.nonce, stack.cookiekey);
    packet_outgoing(stack.cookie1, stack.mc.mctiny.cookieblockbytes);

    /* reply1 */
    packet_clear();
    packet_append(stack.cookie1, stack.mc.mctiny.cookieblockbytes);
    packet_encrypt(stack.nonce, stack.key123);
    byte_copy(packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES,
              mc_proto_NONCEBYTES, stack.nonce);
    packet_outgoing(packet + mc_proto_HEADERBYTES,
                    stack.mc.mctiny.reply1bytes - mc_proto_HEADERBYTES);

    ret = stack.mc.mctiny.reply1bytes;
cleanup:
    byte_zero(&stack, sizeof stack);
    return ret;
}
