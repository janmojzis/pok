#include "byte.h"
#include "packet.h"
#include "client.h"
#include "client_kex.h"

int client_kex_query3_isready(struct client_kex *c, long long p3piecepos,
                              int flagauth) {

    long long piecepos;
    if (p3piecepos < 0 || p3piecepos >= mc_mctiny_P3PIECES) return 0;
    if (flagauth < 0 || flagauth > 1) return 0;
    if (c->flagreply3[flagauth][p3piecepos]) return 0;

    for (piecepos = p3piecepos * mc_mctiny_P3BLOCKS;
         piecepos < (p3piecepos + 1) * mc_mctiny_P3BLOCKS; ++piecepos) {
        if (piecepos < mc_mctiny_PIECES) {
            if (!c->flagreply2[flagauth][piecepos]) return 0;
        }
    }

    return 1;
}

void client_kex_query3(struct client_kex *c, long long p3piecepos,
                       int flagauth) {

    struct stack {
        unsigned char nonce[mc_NONCEBYTES];
        unsigned char packet[packet_MAXBYTES];
    } stack;
    long long i;

    if (!client_kex_query3_isready(c, p3piecepos, flagauth)) return;

    /* set nonce */
    byte_copy(stack.nonce, mc_NONCEBYTES - 2, c->longtermnonce);
    mc_Levpos_store(stack.nonce + mc_NONCEBYTES - 2, 3, p3piecepos, flagauth);

    /* create query3 */
    packet_clear();
    for (i = 0; i < mc_mctiny_P3BLOCKS; ++i) {
        packet_append(c->cookie2[flagauth][p3piecepos * mc_mctiny_P3BLOCKS + i],
                      mc_mctiny_COOKIE2BLOCKBYTES);
    }
    packet_encrypt(stack.nonce, c->key1234query);
    packet_outgoing(stack.packet + mc_HEADERBYTES,
                    mc_mctiny_QUERYK3BYTES - mc_HEADERBYTES);

    /* add magic, routing-extension, nonce */
    byte_copy(stack.packet, mc_MAGICBYTES, mc_MAGICQUERYK);
    byte_copy(stack.packet + mc_MAGICBYTES, mc_EXTENSIONBYTES, c->extension);
    byte_copy(stack.packet + mc_MAGICBYTES + mc_EXTENSIONBYTES, mc_NONCEBYTES,
              stack.nonce);

    /* send query3 */
    client_send(c->fd, stack.packet, mc_mctiny_QUERYK3BYTES, c->ip, c->port);
    pacing_transmitted(&c->pacingc, &c->pacing3[flagauth][p3piecepos]);

    /* cleanup */
    byte_zero(&stack, sizeof stack);
}
