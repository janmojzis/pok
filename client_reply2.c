#include "log.h"
#include "byte.h"
#include "packet.h"
#include "client.h"

void client_reply2(struct client *pc, unsigned char *packet,
                   long long packetlen) {

    struct stack {
        unsigned char nonce[mc_proto_NONCEBYTES];
    } stack;
    unsigned int nonce0, nonce1;
    long long piecepos;

    (void) packetlen;

    /* extract nonce */
    byte_copy(stack.nonce, mc_proto_NONCEBYTES,
              packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES);
    nonce0 = stack.nonce[sizeof stack.nonce - 2];
    nonce1 = stack.nonce[sizeof stack.nonce - 1];

    if (!(nonce0 & 1)) goto cleanup;
    if ((nonce1 & 16)) goto cleanup;
    piecepos = 127 & (nonce0 / 2);
    if (piecepos < 0) goto cleanup; /* impossible */
    if (piecepos >= pc->mc.mctiny.pieces) goto cleanup;
    if (nonce0 != 2 * piecepos + 1) goto cleanup;
    if (nonce1 != 64 + 32) goto cleanup;
    if (pc->flagreply2[piecepos]) goto cleanup;

    /* decrypt packet */
    packet_incoming(packet + mc_proto_HEADERBYTES,
                    pc->mc.mctiny.reply2bytes - mc_proto_HEADERBYTES);
    if (packet_decrypt(stack.nonce, pc->key123) != 0) {
        log_w1("unable to decrypt reply2 packet");
        goto cleanup;
    }
    packet_extract(pc->synd2[piecepos], pc->mc.mctiny.piecebytes);
    if (!packet_isok()) {
        log_b1("unable to parse reply2 packet");
        goto cleanup;
    }

    pacing_acknowledged(&pc->pacingc, &pc->pacing2[piecepos]);
    pc->flagreply2[piecepos] = 1;

cleanup:
    byte_zero(&stack, sizeof stack);
}
