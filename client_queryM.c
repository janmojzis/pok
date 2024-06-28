#include "uint64_pack.h"
#include "log.h"
#include "byte.h"
#include "packet.h"
#include "socket.h"
#include "seconds.h"
#include "client.h"

void client_queryM(struct client_connection *c, unsigned char *message,
                   long long messagelen) {

    struct stack {
        unsigned char nonce[mc_proto_NONCEBYTES];
        unsigned char packet[packet_MAXBYTES];
    } stack;
    long long r;

    /* nonce = id + noncecounter */
    byte_copy(stack.nonce, 16, c->id);
    uint64_pack(stack.nonce + 16, ++(c->clientnonce));

    /* add encrypted content */
    packet_clear();
    packet_append(message, messagelen);
    packet_encrypt(stack.nonce, c->clientkey);
    packet_outgoing(stack.packet + mc_proto_HEADERBYTES,
                    messagelen + mc_proto_AUTHBYTES);

    /* add magic, routing-extension, nonce */
    byte_copy(stack.packet, mc_proto_MAGICBYTES, mc_proto_MAGICQUERYM);
    byte_copy(stack.packet + mc_proto_MAGICBYTES, mc_proto_EXTENSIONBYTES,
              c->extension);
    byte_copy(stack.packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES,
              mc_proto_NONCEBYTES, stack.nonce);

    /* send queryM */
    r = socket_enqueue(c->fd, stack.packet,
                       messagelen + mc_proto_HEADERBYTES + mc_proto_AUTHBYTES,
                       c->ip, c->port);
    if (r == messagelen + mc_proto_HEADERBYTES + mc_proto_AUTHBYTES) {
        log_t8("queryM send, nonce = ",
               log_hex(stack.packet + mc_proto_MAGICBYTES +
                           mc_proto_EXTENSIONBYTES,
                       mc_proto_NONCEBYTES),
               ", ip = ", log_ip(c->ip), ", port = ", log_port(c->port),
               ", len = ", log_num(r));
    }
    else {
        log_w8("queryM send failed, nonce = ",
               log_hex(stack.packet + mc_proto_MAGICBYTES +
                           mc_proto_EXTENSIONBYTES,
                       mc_proto_NONCEBYTES),
               ", ip = ", log_ip(c->ip), ", port = ", log_port(c->port),
               ", len = ", log_num(r));
    }

    byte_zero(&stack, sizeof stack);
    byte_zero(message, messagelen);
}
