#include "log.h"
#include "byte.h"
#include "packet.h"
#include "socket.h"
#include "client.h"

int client_query3_isready(struct client *pc) {

    long long piecepos;

    if (pc->flagcookie9) return 0;
    for (piecepos = 0; piecepos < pc->mc.mctiny.pieces; ++piecepos)
        if (!pc->flagreply2[piecepos]) return 0;
    return 1;
}

void client_query3(struct client *pc) {

    struct stack {
        unsigned char nonce[mc_proto_NONCEBYTES];
        unsigned char packet[packet_MAXBYTES];
    } stack;
    long long r;

    if (!client_query3_isready(pc)) return;

    byte_copy(stack.nonce, sizeof stack.nonce, pc->longtermnonce);
    stack.nonce[sizeof stack.nonce - 2] = 254;
    stack.nonce[sizeof stack.nonce - 1] = 255;

    mc_mctiny_mergepieces(&pc->mc, pc->synd3, pc->synd2);

    /* create query3 */
    packet_clear();
    packet_append(pc->synd3, pc->mc.mctiny.colbytes);
    packet_encrypt(stack.nonce, pc->key123);
    packet_outgoing(stack.packet + mc_proto_HEADERBYTES,
                    pc->mc.mctiny.query3bytes - mc_proto_HEADERBYTES);

    /* add magic, routing-extension, nonce */
    byte_copy(stack.packet, mc_proto_MAGICBYTES, mc_proto_MAGICQUERY3);
    byte_copy(stack.packet + mc_proto_MAGICBYTES, mc_proto_EXTENSIONBYTES,
              pc->extension);
    byte_copy(stack.packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES,
              mc_proto_NONCEBYTES, stack.nonce);

    /* send query3 */
    r = socket_enqueue(pc->fd, stack.packet, pc->mc.mctiny.query3bytes,
                       pc->serverip, pc->serverport);
    if (r == pc->mc.mctiny.query3bytes) {
        log_t8("query3 send, nonce = ",
               log_hex(stack.packet + mc_proto_MAGICBYTES +
                           mc_proto_EXTENSIONBYTES,
                       mc_proto_NONCEBYTES),
               ", ip = ", log_ip(pc->serverip),
               ", port = ", log_port(pc->serverport), ", len = ", log_num(r));
    }
    else {
        log_w8("query3 send failed, nonce = ",
               log_hex(stack.packet + mc_proto_MAGICBYTES +
                           mc_proto_EXTENSIONBYTES,
                       mc_proto_NONCEBYTES),
               ", ip = ", log_ip(pc->serverip),
               ", port = ", log_port(pc->serverport), ", len = ", log_num(r));
    }
    pacing_transmitted(&pc->pacingc, &pc->pacing3);

    byte_zero(&stack, sizeof stack);
}
