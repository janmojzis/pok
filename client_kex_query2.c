#include "byte.h"
#include "packet.h"
#include "client.h"
#include "client_kex.h"

int client_kex_query2_isready(struct client_kex *c, long long piecepos,
                              int flagauth) {

    long long rowpos, colpos;

    if (piecepos < 0 || piecepos >= mc_mctiny_PIECES) return 0;
    if (flagauth < 0 || flagauth > 1) return 0;
    if (c->flagreply2[flagauth][piecepos]) return 0;

    for (rowpos = piecepos * mc_mctiny_V; rowpos < (piecepos + 1) * mc_mctiny_V;
         ++rowpos)
        if (rowpos >= 0 && rowpos < mc_mctiny_ROWBLOCKS)
            for (colpos = 0; colpos < mc_mctiny_COLBLOCKS; ++colpos)
                if (!c->flagreply1[flagauth]
                                  [rowpos * mc_mctiny_COLBLOCKS + colpos])
                    return 0;

    return 1;
}

void client_kex_query2(struct client_kex *c, long long piecepos, int flagauth) {

    struct stack {
        unsigned char nonce[mc_NONCEBYTES];
        unsigned char packet[packet_MAXBYTES];
    } stack;
    long long rowpos;
    long long colpos;

    if (!client_kex_query2_isready(c, piecepos, flagauth)) return;

    /* set nonce */
    byte_copy(stack.nonce, mc_NONCEBYTES - 2, c->longtermnonce);
    mc_Levpos_store(stack.nonce + mc_NONCEBYTES - 2, 2, piecepos, flagauth);

    /* create query2 */
    packet_clear();
    for (rowpos = piecepos * mc_mctiny_V; rowpos < (piecepos + 1) * mc_mctiny_V;
         ++rowpos) {
        for (colpos = 0; colpos < mc_mctiny_COLBLOCKS; ++colpos) {
            if (rowpos >= 0 && rowpos < mc_mctiny_ROWBLOCKS) {
                packet_append(
                    c->cookie1[flagauth][rowpos * mc_mctiny_COLBLOCKS + colpos],
                    mc_mctiny_COOKIE1BLOCKBYTES);
            }
            else {
                byte_zero(c->blankcookie1, sizeof c->blankcookie1);
                packet_append(
                    c->blankcookie1,
                    mc_mctiny_COOKIE1BLOCKBYTES); /* XXX: could compress */
            }
        }
    }
    packet_encrypt(stack.nonce, c->key1234query);
    packet_outgoing(stack.packet + mc_HEADERBYTES,
                    mc_mctiny_QUERYK2BYTES - mc_HEADERBYTES);

    /* add magic, routing-extension, nonce */
    byte_copy(stack.packet, mc_MAGICBYTES, mc_MAGICQUERYK);
    byte_copy(stack.packet + mc_MAGICBYTES, mc_EXTENSIONBYTES, c->extension);
    byte_copy(stack.packet + mc_MAGICBYTES + mc_EXTENSIONBYTES, mc_NONCEBYTES,
              stack.nonce);

    /* send query2 */
    client_send(c->fd, stack.packet, mc_mctiny_QUERYK2BYTES, c->ip, c->port);
    pacing_transmitted(&c->pacingc, &c->pacing2[flagauth][piecepos]);

    /* cleanup */
    byte_zero(&stack, sizeof stack);
}
