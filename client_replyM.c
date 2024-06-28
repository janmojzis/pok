#include "uint64_unpack.h"
#include "log.h"
#include "byte.h"
#include "packet.h"
#include "seconds.h"
#include "client.h"

long long client_replyM(struct client_connection *c, unsigned char *message,
                        unsigned char *packet, long long packetlen) {

    struct stack {
        unsigned char nonce[mc_proto_NONCEBYTES];
    } stack;
    uint64_t packetnoncecounter;
    long long messagelen = -1;

    /* extract nonce */
    byte_copy(stack.nonce, mc_proto_NONCEBYTES,
              packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES);
    packetnoncecounter = uint64_unpack(stack.nonce + 16);
    if (packetnoncecounter <= c->servernonce) {
        double tm =
            (seconds() - c->receivedtm) * (c->servernonce - packetnoncecounter);
        if (tm > 0.1) {
            log_w4("received nonce <= last-nonce, nonce = ",
                   log_num(packetnoncecounter),
                   ", last-nonce = ", log_num(c->servernonce));
            goto cleanup;
        }
    }

    /* decrypt packet */
    packet_incoming(packet + mc_proto_HEADERBYTES,
                    packetlen - mc_proto_HEADERBYTES);
    if (packet_decrypt(stack.nonce, c->serverkey) != 0) {
        log_w1("unable to decrypt replyM packet");
        goto cleanup;
    }
    packet_extract(message,
                   packetlen - mc_proto_HEADERBYTES - mc_proto_AUTHBYTES);
    if (!packet_isok()) {
        log_b1("unable to parse replyM packet");
        goto cleanup;
    }
    messagelen = packetlen - mc_proto_HEADERBYTES - mc_proto_AUTHBYTES;

    /* update nonce, store recv. time */
    c->servernonce = packetnoncecounter;
    c->receivedtm = seconds();

cleanup:
    byte_zero(&stack, sizeof stack);
    return messagelen;
}
