#include "log.h"
#include "byte.h"
#include "packet.h"
#include "client_kex.h"

void client_kex_reply3(struct client_kex *c, unsigned char *packet,
                       long long packetlen, unsigned char *nonce,
                       long long l3pos, int flagauth) {

    if (!client_kex_query3_isready(c, l3pos, flagauth)) return;

    /* decrypt/extract packet */
    packet_incoming(packet, packetlen);
    if (packet_decrypt(nonce, c->key1234reply) != 0) {
        log_w1("key-exchange: reply3: unable to decrypt packet");
        return;
    }
    packet_extract(c->cookie3[flagauth][l3pos], mc_mctiny_COOKIE3BLOCKBYTES);
    if (!packet_isok()) {
        log_w1("key-exchange: reply3: unable to parse packet");
        return;
    }

    pacing_acknowledged(&c->pacingc, &c->pacing3[flagauth][l3pos]);
    c->flagreply3[flagauth][l3pos] = 1;
}
