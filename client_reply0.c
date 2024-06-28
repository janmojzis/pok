#include "log.h"
#include "byte.h"
#include "packet.h"
#include "client.h"

void client_reply0(struct client *pc, unsigned char *packet,
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
    if (nonce1 & 64) goto cleanup;
    if (nonce0 != 1) goto cleanup;
    if (nonce1) goto cleanup;
    if (pc->flagreply0) goto cleanup;

    /* decrypt packet */
    packet_incoming(packet + mc_proto_HEADERBYTES,
                    pc->mc.mctiny.reply0bytes - mc_proto_HEADERBYTES);
    packet_extract(pc->key0 + 2 * packet_KEYBYTES, packet_KEYBYTES);
    packet_extract(pc->ciphertext, sizeof pc->ciphertext);
    mc_keys_authdec(pc->key0 + packet_KEYBYTES, pc->ciphertext,
                    pc->serverauthpkhash);
    mceliece_xof_shake256(pc->key0, packet_KEYBYTES, pc->key0, sizeof pc->key0);
    if (packet_decrypt(stack.nonce, pc->key0) != 0) {
        log_w1("unable to decrypt reply0 packet");
        goto cleanup;
    }
    packet_extract(pc->key123, sizeof pc->key123);
    if (!packet_isok()) {
        log_b1("unable to parse reply0 packet");
        goto cleanup;
    }

    /* packet is verified, store nonce, ip, port */
    byte_copy(pc->longtermnonce, sizeof stack.nonce, stack.nonce);
    byte_copy(pc->serverip, 16, pc->packetip);
    byte_copy(pc->serverport, 2, pc->packetport);
    byte_zero(pc->key0, sizeof pc->key0);
    log_d2("client id: ", log_hex(pc->longtermnonce, 16));

    pacing_acknowledged(&pc->pacingc, &pc->pacing0);
    pc->flagreply0 = 1;

cleanup:
    byte_zero(&stack, sizeof stack);
}
