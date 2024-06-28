#include <randombytes.h>
#include "log.h"
#include "byte.h"
#include "socket.h"
#include "packet.h"
#include "client.h"

int client_query0_isready(struct client *pc) { return !pc->flagreply0; }

void client_query0_prepare(struct client *pc) {

    struct stack {
        unsigned char box[512];
        unsigned char nonce[mc_proto_NONCEBYTES];
    } stack;

    /* set initial nonce */
    randombytes(stack.nonce, sizeof stack.nonce);
    stack.nonce[sizeof stack.nonce - 3] = pc->mc.id;
    stack.nonce[sizeof stack.nonce - 2] = 0;
    stack.nonce[sizeof stack.nonce - 1] = 0;

    /* copy authorization public-key hash */
    byte_zero(stack.box, sizeof stack.box);
    byte_copy(stack.box, sizeof pc->serverauthpkhash, pc->serverauthpkhash);

    /* create query0 */
    packet_clear();
    packet_append(stack.box, sizeof stack.box);
    packet_encrypt(stack.nonce, pc->key0);
    packet_append(pc->serverpkhash, mc_HASHBYTES);
    packet_append(pc->ciphertext, sizeof pc->ciphertext);
    packet_outgoing(pc->query0 + mc_proto_HEADERBYTES,
                    sizeof pc->query0 - mc_proto_HEADERBYTES);

    /* add magic, routing-extension, nonce */
    byte_copy(pc->query0, mc_proto_MAGICBYTES, mc_proto_MAGICQUERY0);
    byte_copy(pc->query0 + mc_proto_MAGICBYTES, mc_proto_EXTENSIONBYTES,
              pc->extension);
    byte_copy(pc->query0 + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES,
              mc_proto_NONCEBYTES, stack.nonce);

    /* cleanup */
    byte_zero(&stack, sizeof stack);
}

void client_query0_do(struct client *pc) {

    long long r;

    r = socket_enqueue(pc->fd, pc->query0, sizeof pc->query0,
                       pc->serverip + pc->serverippos, pc->serverport);

    if (r == sizeof pc->query0) {
        log_t8(
            "query0 send, nonce = ",
            log_hex(pc->query0 + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES,
                    mc_proto_NONCEBYTES),
            ", ip = ", log_ip(pc->serverip + pc->serverippos),
            ", port = ", log_port(pc->serverport), ", len = ", log_num(r));
    }
    else {
        log_w8(
            "query0 send failed, nonce = ",
            log_hex(pc->query0 + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES,
                    mc_proto_NONCEBYTES),
            ", ip = ", log_ip(pc->serverip + pc->serverippos),
            ", port = ", log_port(pc->serverport), ", len = ", log_num(r));
    }

    pc->serverippos = (pc->serverippos + 16) % pc->serveriplen;
    pacing_transmitted(&pc->pacingc, &pc->pacing0);
}
