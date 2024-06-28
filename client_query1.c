#include "log.h"
#include "byte.h"
#include "socket.h"
#include "packet.h"
#include "client.h"

int client_query1_isready(struct client *pc, long long rowpos,
                          long long colpos) {
    if (rowpos < 0) return 0;                        /* internal bug */
    if (rowpos >= pc->mc.mctiny.rowblocks) return 0; /* internal bug */
    if (colpos < 0) return 0;                        /* internal bug */
    if (colpos >= pc->mc.mctiny.colblocks) return 0; /* internal bug */
    if (pc->flagreply1[rowpos][colpos]) return 0;
    if (!pc->flagreply0) return 0;
    return 1;
}

void client_query1(struct client *pc, long long rowpos, long long colpos) {

    struct stack {
        unsigned char nonce[mc_proto_NONCEBYTES];
        unsigned char packet[packet_MAXBYTES];
    } stack;
    long long r;

    if (!client_query1_isready(pc, rowpos, colpos)) return;

    mc_mctiny_pk2block(&pc->mc, pc->block, pc->clientpk, rowpos, colpos);

    /* rowpos is "i-1" in spec */
    /* colpos is "j-1" in spec */
    byte_copy(stack.nonce, sizeof stack.nonce, pc->longtermnonce);
    stack.nonce[sizeof stack.nonce - 2] = rowpos * 2;
    stack.nonce[sizeof stack.nonce - 1] = 64 + colpos;

    /* create query1 */
    packet_clear();
    packet_append(pc->block, pc->mc.mctiny.blockbytes);
    packet_encrypt(stack.nonce, pc->key123);
    packet_outgoing(stack.packet + mc_proto_HEADERBYTES,
                    pc->mc.mctiny.query1bytes - mc_proto_HEADERBYTES);

    /* add magic, routing-extension, nonce */
    byte_copy(stack.packet, mc_proto_MAGICBYTES, mc_proto_MAGICQUERY1);
    byte_copy(stack.packet + mc_proto_MAGICBYTES, mc_proto_EXTENSIONBYTES,
              pc->extension);
    byte_copy(stack.packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES,
              mc_proto_NONCEBYTES, stack.nonce);

    /* send query1 */
    r = socket_enqueue(pc->fd, stack.packet, pc->mc.mctiny.query1bytes,
                       pc->serverip, pc->serverport);
    if (r == pc->mc.mctiny.query1bytes) {
        log_t8("query1 send, nonce = ",
               log_hex(stack.packet + mc_proto_MAGICBYTES +
                           mc_proto_EXTENSIONBYTES,
                       mc_proto_NONCEBYTES),
               ", ip = ", log_ip(pc->serverip),
               ", port = ", log_port(pc->serverport), ", len = ", log_num(r));
    }
    else {
        log_w8("query1 send failed, nonce = ",
               log_hex(stack.packet + mc_proto_MAGICBYTES +
                           mc_proto_EXTENSIONBYTES,
                       mc_proto_NONCEBYTES),
               ", ip = ", log_ip(pc->serverip),
               ", port = ", log_port(pc->serverport), ", len = ", log_num(r));
    }
    pacing_transmitted(&pc->pacingc, &pc->pacing1[rowpos][colpos]);

    byte_zero(&stack, sizeof stack);
}
