#include "log.h"
#include "byte.h"
#include "packet.h"
#include "client.h"

void client_reply3(struct client *pc, unsigned char *packet,
                   long long packetlen) {

    struct stack {
        unsigned char nonce[mc_proto_NONCEBYTES];
    } stack;
    unsigned int nonce0, nonce1;

    (void) packetlen;

    /* extract nonce */
    byte_copy(stack.nonce, mc_proto_NONCEBYTES,
              packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES);
    nonce0 = stack.nonce[sizeof stack.nonce - 2];
    nonce1 = stack.nonce[sizeof stack.nonce - 1];

    if (!(nonce0 & 1)) goto cleanup;
    if (nonce0 != 255) goto cleanup;
    if (nonce1 != 255) goto cleanup;
    if (pc->flagcookie9) goto cleanup;

    /* decrypt packet */
    packet_incoming(packet + mc_proto_HEADERBYTES,
                    pc->mc.mctiny.reply3bytes - mc_proto_HEADERBYTES);
    if (packet_decrypt(stack.nonce, pc->key123) != 0) {
        log_w1("unable to decrypt reply3 packet");
        goto cleanup;
    }
    packet_extract(pc->ciphertext, sizeof pc->ciphertext);
    packet_extract(pc->cookie9, sizeof pc->cookie9);
    if (!packet_isok()) {
        log_b1("unable to parse reply3 packet");
        goto cleanup;
    }

    pacing_acknowledged(&pc->pacingc, &pc->pacing3);
    pc->flagcookie9 = 1;

cleanup:
    byte_zero(&stack, sizeof stack);
}
