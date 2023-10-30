#include "log.h"
#include "byte.h"
#include "packet.h"
#include "client_kex.h"

void client_kex_reply4(struct client_kex *c, unsigned char *packet,
                       long long packetlen, unsigned char *nonce) {

    if (!client_kex_query4_isready(c)) return;

    /* decrypt packet */
    packet_incoming(packet, packetlen);
    if (packet_decrypt(nonce, c->key1234reply) != 0) {
        log_w1("key-exchange: reply4: unable to decrypt packet");
        return;
    }
    packet_extract(c->ciphertext1, sizeof c->ciphertext1);
    packet_extract(c->ciphertext0, sizeof c->ciphertext0);
    packet_extract(c->cookie9, sizeof c->cookie9);
    if (!packet_isok()) {
        log_w1("key-exchange: reply4: unable to parse packet");
        return;
    }

    pacing_acknowledged(&c->pacingc, &c->pacing4);
    c->flagreply4 = 1;
}
