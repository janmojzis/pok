#include <randombytes.h>
#include "byte.h"
#include "log.h"
#include "client_kex.h"

int client_kex_query0_isready(struct client_kex *c) { return !c->flagreply0; }

void client_kex_query0_prepare(struct client_kex *c) {

    struct stack {
        unsigned char box[512];
        unsigned char nonce[mc_NONCEBYTES];
    } stack;

    /* set initial nonce */
    randombytes(stack.nonce, mc_NONCEBYTES - 2);
    mc_Levpos_store(stack.nonce + mc_NONCEBYTES - 2, 0, 0, 0);

    byte_zero(stack.box, sizeof stack.box);

    /* create query0 */
    packet_clear();
    packet_append(stack.box, sizeof stack.box);
    packet_encrypt(stack.nonce, c->key0query);
    packet_append(c->pkhash, mc_HASHBYTES);
    packet_append(c->ciphertext, sizeof c->ciphertext);
    packet_outgoing(c->query0 + mc_HEADERBYTES,
                    sizeof c->query0 - mc_HEADERBYTES);

    /* add magic, routing-extension, nonce */
    byte_copy(c->query0, mc_MAGICBYTES, mc_MAGICQUERYK);
    byte_copy(c->query0 + mc_MAGICBYTES, mc_EXTENSIONBYTES, c->extension);
    byte_copy(c->query0 + mc_MAGICBYTES + mc_EXTENSIONBYTES, mc_NONCEBYTES,
              stack.nonce);

    /* cleanup */
    byte_zero(&stack, sizeof stack);
}

void client_kex_query0(struct client_kex *c, long long pos) {

    if (!client_kex_query0_isready(c)) return;
    client_send(c->fd, c->query0, sizeof c->query0, c->ip + pos, c->port);
    pacing_transmitted(&c->pacingc, &c->pacing0[pos / socket_IPBYTES]);
}
