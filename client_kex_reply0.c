#include "log.h"
#include "byte.h"
#include "packet.h"
#include "client_kex.h"

void client_kex_reply0(struct client_kex *c, unsigned char *packet,
                       long long packetlen, unsigned char *nonce) {

    long long i;

    if (!client_kex_query0_isready(c)) return;

    /* decrypt/extract packet */
    packet_incoming(packet, packetlen);
    if (packet_decrypt(nonce, c->key0reply) != 0) {
        log_w1("key-exchange: reply0: unable to decrypt packet");
        goto cleanup;
    }
    packet_extract(c->key1234reply, sizeof c->key1234reply);
    packet_extract(c->key1234query, sizeof c->key1234query);
    if (!packet_isok()) {
        log_w1("key-exchange: reply0: unable to parse packet");
        goto cleanup;
    }

    /* packet is verified, store longtermnonce, drop key0 */
    byte_copy(c->longtermnonce, mc_NONCEBYTES, nonce);
    byte_zero(c->key0query, sizeof c->key0query);
    byte_zero(c->key0reply, sizeof c->key0reply);

    for (i = 0; i < c->iplen; i += socket_IPBYTES) {
        if (byte_isequal(c->packetip, socket_IPBYTES, c->ip + i)) {
            byte_swap(c->ip, socket_IPBYTES, c->ip + i);
            break;
        }
    }
    for (i = 0; i < c->iplen; i += socket_IPBYTES) {
        pacing_acknowledged(&c->pacingc, &c->pacing0[i / socket_IPBYTES]);
    }

    c->flagreply0 = 1;

cleanup:
    return;
}
