#include "log.h"
#include "byte.h"
#include "packet.h"
#include "client_kex.h"

void client_kex_reply2(struct client_kex *c, unsigned char *packet,
                       long long packetlen, unsigned char *nonce,
                       long long piecepos, int flagauth) {

    if (!client_kex_query2_isready(c, piecepos, flagauth)) return;

    /* decrypt/extract packet */
    packet_incoming(packet, packetlen);
    if (packet_decrypt(nonce, c->key1234reply) != 0) {
        log_w1("key-exchange: reply2: unable to decrypt packet");
        return;
    }
    packet_extract(c->cookie2[flagauth][piecepos], mc_mctiny_COOKIE2BLOCKBYTES);
    if (!packet_isok()) {
        log_w1("key-exchange: reply2: unable to parse packet");
        return;
    }

    pacing_acknowledged(&c->pacingc, &c->pacing2[flagauth][piecepos]);
    c->flagreply2[flagauth][piecepos] = 1;
}
