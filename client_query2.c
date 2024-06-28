#include "log.h"
#include "byte.h"
#include "socket.h"
#include "packet.h"
#include "client.h"

int client_query2_isready(struct client *pc, long long piecepos) {

    long long rowpos, colpos;

    if (piecepos < 0) return 0; /* internal bug */
    if (pc->flagreply2[piecepos]) return 0;

    for (rowpos = piecepos * pc->mc.mctiny.v;
         rowpos < (piecepos + 1) * pc->mc.mctiny.v; ++rowpos)
        if (rowpos >= 0 && rowpos < pc->mc.mctiny.rowblocks)
            for (colpos = 0; colpos < pc->mc.mctiny.colblocks; ++colpos)
                if (!pc->flagreply1[rowpos][colpos]) return 0;

    return 1;
}

void client_query2(struct client *pc, long long piecepos) {

    struct stack {
        unsigned char nonce[mc_proto_NONCEBYTES];
        unsigned char packet[packet_MAXBYTES];
    } stack;
    long long rowpos, colpos, r;

    if (!client_query2_isready(pc, piecepos)) return;

    byte_copy(stack.nonce, sizeof stack.nonce, pc->longtermnonce);
    stack.nonce[sizeof stack.nonce - 2] = piecepos * 2;
    stack.nonce[sizeof stack.nonce - 1] = 64 + 32;

    /* create query2 */
    packet_clear();
    for (rowpos = piecepos * pc->mc.mctiny.v;
         rowpos < (piecepos + 1) * pc->mc.mctiny.v; ++rowpos) {
        for (colpos = 0; colpos < pc->mc.mctiny.colblocks; ++colpos) {
            if (rowpos >= 0 && rowpos < pc->mc.mctiny.rowblocks) {
                packet_append(pc->cookie1[rowpos][colpos],
                              pc->mc.mctiny.cookieblockbytes);
            }
            else {
                byte_zero(pc->blankcookie1, sizeof pc->blankcookie1);
                packet_append(
                    pc->blankcookie1,
                    pc->mc.mctiny.cookieblockbytes); /* XXX: could compress */
            }
        }
    }
    packet_encrypt(stack.nonce, pc->key123);
    packet_outgoing(stack.packet + mc_proto_HEADERBYTES,
                    pc->mc.mctiny.query2bytes - mc_proto_HEADERBYTES);

    /* add magic, routing-extension, nonce */
    byte_copy(stack.packet, mc_proto_MAGICBYTES, mc_proto_MAGICQUERY2);
    byte_copy(stack.packet + mc_proto_MAGICBYTES, mc_proto_EXTENSIONBYTES,
              pc->extension);
    byte_copy(stack.packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES,
              mc_proto_NONCEBYTES, stack.nonce);

    /* send query2 */
    r = socket_enqueue(pc->fd, stack.packet, pc->mc.mctiny.query2bytes,
                       pc->serverip, pc->serverport);
    if (r == pc->mc.mctiny.query2bytes) {
        log_t8("query2 send, nonce = ",
               log_hex(stack.packet + mc_proto_MAGICBYTES +
                           mc_proto_EXTENSIONBYTES,
                       mc_proto_NONCEBYTES),
               ", ip = ", log_ip(pc->serverip),
               ", port = ", log_port(pc->serverport), ", len = ", log_num(r));
    }
    else {
        log_w8("query2 send failed, nonce = ",
               log_hex(stack.packet + mc_proto_MAGICBYTES +
                           mc_proto_EXTENSIONBYTES,
                       mc_proto_NONCEBYTES),
               ", ip = ", log_ip(pc->serverip),
               ", port = ", log_port(pc->serverport), ", len = ", log_num(r));
    }
    pacing_transmitted(&pc->pacingc, &pc->pacing2[piecepos]);

    byte_zero(&stack, sizeof stack);
}
