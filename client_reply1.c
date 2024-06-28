#include "log.h"
#include "byte.h"
#include "packet.h"
#include "client.h"

void client_reply1(struct client *pc, unsigned char *packet,
                   long long packetlen) {

    struct stack {
        unsigned char nonce[mc_proto_NONCEBYTES];
    } stack;
    unsigned int nonce0, nonce1;
    long long rowpos, colpos;

    (void) packetlen;

    /* extract nonce */
    byte_copy(stack.nonce, mc_proto_NONCEBYTES,
              packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES);
    nonce0 = stack.nonce[sizeof stack.nonce - 2];
    nonce1 = stack.nonce[sizeof stack.nonce - 1];

    if (!(nonce0 & 1)) goto cleanup;
    if ((nonce1 & 32)) goto cleanup;
    rowpos = 127 & (nonce0 / 2);
    colpos = 31 & nonce1;
    if (rowpos < 0) goto cleanup; /* impossible */
    if (colpos < 0) goto cleanup; /* impossible */
    if (rowpos >= pc->mc.mctiny.rowblocks) goto cleanup;
    if (colpos >= pc->mc.mctiny.colblocks) goto cleanup;
    if (nonce0 != 2 * rowpos + 1) goto cleanup;
    if (nonce1 != 64 + colpos) goto cleanup;
    if (pc->flagreply1[rowpos][colpos]) goto cleanup;

    /* decrypt packet */
    packet_incoming(packet + mc_proto_HEADERBYTES,
                    pc->mc.mctiny.reply1bytes - mc_proto_HEADERBYTES);
    if (packet_decrypt(stack.nonce, pc->key123) != 0) {
        log_w1("unable to decrypt reply1 packet");
        goto cleanup;
    }
    packet_extract(pc->cookie1[rowpos][colpos], pc->mc.mctiny.cookieblockbytes);
    if (!packet_isok()) {
        log_b1("unable to parse reply1 packet");
        goto cleanup;
    }

    pacing_acknowledged(&pc->pacingc, &pc->pacing1[rowpos][colpos]);
    pc->flagreply1[rowpos][colpos] = 1;

cleanup:
    byte_zero(&stack, sizeof stack);
}
