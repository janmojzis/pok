#include "byte.h"
#include "log.h"
#include "client_kex.h"

int client_kex_query1_isready(struct client_kex *c, long long pos,
                              int flagauth) {

    if (pos < 0 || pos >= mc_mctiny_BLOCKS) return 0;
    if (flagauth < 0 || flagauth > 1) return 0;
    if (c->flagreply1[flagauth][pos]) return 0;
    if (!c->flagreply0) return 0;
    return 1;
}

void client_kex_query1(struct client_kex *c, long long pos, int flagauth) {

    struct stack {
        unsigned char nonce[mc_NONCEBYTES];
        unsigned char packet[packet_MAXBYTES];
    } stack;
    long long rowpos, colpos;

    if (!client_kex_query1_isready(c, pos, flagauth)) return;

    rowpos = pos / mc_mctiny_COLBLOCKS;
    colpos = pos % mc_mctiny_COLBLOCKS;
    if (flagauth) { mc_mctiny_pk2block(c->block, c->authpk, rowpos, colpos); }
    else { mc_mctiny_pk2block(c->block, c->clientpk, rowpos, colpos); }

    /* set nonce */
    byte_copy(stack.nonce, mc_NONCEBYTES - 2, c->longtermnonce);
    mc_Levpos_store(stack.nonce + mc_NONCEBYTES - 2, 1, pos, flagauth);

    /* create query1 */
    packet_clear();
    packet_append(c->block, mc_mctiny_BLOCKBYTES);
    packet_encrypt(stack.nonce, c->key1234query);
    packet_outgoing(stack.packet + mc_HEADERBYTES,
                    mc_mctiny_QUERYK1BYTES - mc_HEADERBYTES);

    /* add magic, routing-extension, nonce */
    byte_copy(stack.packet, mc_MAGICBYTES, mc_MAGICQUERYK);
    byte_copy(stack.packet + mc_MAGICBYTES, mc_EXTENSIONBYTES, c->extension);
    byte_copy(stack.packet + mc_MAGICBYTES + mc_EXTENSIONBYTES, mc_NONCEBYTES,
              stack.nonce);

    /* send query1 */
    client_send(c->fd, stack.packet, mc_mctiny_QUERYK1BYTES, c->ip, c->port);
    pacing_transmitted(&c->pacingc, &c->pacing1[flagauth][pos]);

    /* cleanup */
    byte_zero(&stack, sizeof stack);
}
