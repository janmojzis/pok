#include "packet.h"
#include "byte.h"
#include "uint64_pack.h"
#include "uint64_unpack.h"
#include "seconds.h"
#include "log.h"
#include "server.h"

long long server_replyM(struct server_activeclient *c, unsigned char *packet,
                        unsigned char *message, long long messagelen) {

    if (messagelen < 0) return -1;

    /* nonce = id + noncecounter */
    uint64_pack(c->nonce + 16, ++(c->servernonce));

    /* add encrypted content */
    packet_clear();
    packet_append(message, messagelen);
    packet_encrypt(c->nonce, c->serverkey);
    packet_outgoing(packet + mc_proto_HEADERBYTES,
                    messagelen + mc_proto_AUTHBYTES);

    /* add magic, routing-extension, nonce */
    byte_copy(packet, mc_proto_MAGICBYTES, mc_proto_MAGICREPLYM);
    byte_copy(packet + mc_proto_MAGICBYTES, mc_proto_EXTENSIONBYTES,
              c->extension);
    byte_copy(packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES,
              mc_proto_NONCEBYTES, c->nonce);

    return messagelen + mc_proto_HEADERBYTES + mc_proto_AUTHBYTES;
}

long long server_queryM(struct server_activeclient *c, unsigned char *message,
                        unsigned char *packet, long long packetlen,
                        unsigned char *packetip, unsigned char *packetport,
                        unsigned char *packetextension) {

    long long messagelen = -1;
    uint64_t packetnoncecounter = uint64_unpack(packet + mc_proto_MAGICBYTES +
                                                mc_proto_EXTENSIONBYTES + 16);

    if (packetnoncecounter <= c->clientnonce) {
        double tm =
            (seconds() - c->receivedtm) * (c->clientnonce - packetnoncecounter);

        if (tm > 0.1) {
            log_w4("received nonce <= last-nonce, nonce = ",
                   log_num(packetnoncecounter),
                   ", last-nonce = ", log_num(c->clientnonce));
            goto cleanup;
        }
    }

    packet_incoming(packet + mc_proto_HEADERBYTES,
                    packetlen - mc_proto_HEADERBYTES);
    if (packet_decrypt(packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES,
                       c->clientkey) != 0) {
        log_w1("unable to decrypt queryM packet");
        goto cleanup;
    }
    packet_extract(message,
                   packetlen - mc_proto_HEADERBYTES - mc_proto_AUTHBYTES);
    if (!packet_isok()) {
        log_w1("unable to parse queryM packet");
        goto cleanup;
    }

    /* packet is verified, is safe to refresh ip/port/extension
     */
    byte_copy(c->clientip, 16, packetip);
    byte_copy(c->clientport, 2, packetport);
    byte_copy(c->extension, sizeof c->extension, packetextension);

    c->clientnonce = packetnoncecounter;
    c->receivedtm = seconds();
    messagelen = packetlen - mc_proto_HEADERBYTES - mc_proto_AUTHBYTES;

cleanup:
    return messagelen;
}
