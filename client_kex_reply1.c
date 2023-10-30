#include "log.h"
#include "byte.h"
#include "packet.h"
#include "client_kex.h"

void client_kex_reply1(struct client_kex *c, unsigned char *packet,
                       long long packetlen, unsigned char *nonce, long long pos,
                       int flagauth) {

    if (!client_kex_query1_isready(c, pos, flagauth)) return;

    /* decrypt/extract packet */
    packet_incoming(packet, packetlen);
    if (packet_decrypt(nonce, c->key1234reply) != 0) {
        log_w1("key-exchange: reply1: unable to decrypt packet");
        return;
    }
    packet_extract(c->cookie1[flagauth][pos], mc_mctiny_COOKIE1BLOCKBYTES);
    if (!packet_isok()) {
        log_w1("key-exchange: reply1: unable to parse packet");
        return;
    }

    pacing_acknowledged(&c->pacingc, &c->pacing1[flagauth][pos]);
    c->flagreply1[flagauth][pos] = 1;
}
