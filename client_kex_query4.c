#include "byte.h"
#include "packet.h"
#include "client.h"
#include "client_kex.h"

int client_kex_query4_isready(struct client_kex *c) {

    long long piecepos;
    int flagauth;

    if (c->flagreply4) return 0;
    for (flagauth = 0; flagauth < 2; ++flagauth) {
        for (piecepos = 0; piecepos < mc_mctiny_P3PIECES; ++piecepos) {
            if (!c->flagreply3[flagauth][piecepos]) return 0;
        }
    }
    return 1;
}

void client_kex_query4(struct client_kex *c) {

    struct stack {
        unsigned char nonce[mc_NONCEBYTES];
        unsigned char packet[packet_MAXBYTES];
    } stack;
    long long i;
    int flagauth;

    if (!client_kex_query4_isready(c)) return;

    byte_copy(stack.nonce, sizeof stack.nonce, c->longtermnonce);
    mc_Levpos_store(stack.nonce + mc_NONCEBYTES - 2, 4, 0, 0);

    /* create query4 */
    packet_clear();
    for (flagauth = 0; flagauth < 2; ++flagauth) {
        for (i = 0; i < mc_mctiny_P3PIECES; ++i) {
            packet_append(c->cookie3[flagauth][i], mc_mctiny_COOKIE3BLOCKBYTES);
        }
    }
    packet_encrypt(stack.nonce, c->key1234query);
    packet_outgoing(stack.packet + mc_HEADERBYTES,
                    mc_mctiny_QUERYK4BYTES - mc_HEADERBYTES);

    /* add magic, routing-extension, nonce */
    byte_copy(stack.packet, mc_MAGICBYTES, mc_MAGICQUERYK);
    byte_copy(stack.packet + mc_MAGICBYTES, mc_EXTENSIONBYTES, c->extension);
    byte_copy(stack.packet + mc_MAGICBYTES + mc_EXTENSIONBYTES, mc_NONCEBYTES,
              stack.nonce);

    /* send query4 */
    client_send(c->fd, stack.packet, mc_mctiny_QUERYK4BYTES, c->ip, c->port);
    pacing_transmitted(&c->pacingc, &c->pacing4);

    /* cleanup */
    byte_zero(&stack, sizeof stack);
}
