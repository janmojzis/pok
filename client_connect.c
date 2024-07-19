#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <mceliece.h>
#include <randombytes.h>
#include "pacing.h"
#include "seconds.h"
#include "log.h"
#include "byte.h"
#include "mc.h"
#include "extension.h"
#include "socket.h"
#include "randommod.h"
#include "client.h"

#define SCHEDULING_TOLERANCE 0.001

static double trytransmitting(struct client *pc, double when) {

    long long piecepos, rowpos, colpos;
    double when2;

    if (client_query0_isready(pc)) {
        when2 = pacing_whenrto(&pc->pacingc, &pc->pacing0);
        if (when2 <= SCHEDULING_TOLERANCE) {
            client_query0_do(pc);
            return 0;
        }
        if (when2 < when) when = when2;
    }

    for (rowpos = 0; rowpos < pc->mc.mctiny.rowblocks; ++rowpos) {
        for (colpos = 0; colpos < pc->mc.mctiny.colblocks; ++colpos) {
            if (client_query1_isready(pc, rowpos, colpos)) {
                when2 =
                    pacing_whenrto(&pc->pacingc, &pc->pacing1[rowpos][colpos]);
                if (when2 <= SCHEDULING_TOLERANCE) {
                    client_query1(pc, rowpos, colpos);
                    return 0;
                }
                if (when2 < when) when = when2;
            }
        }
    }

    for (piecepos = 0; piecepos < pc->mc.mctiny.pieces; ++piecepos) {
        if (client_query2_isready(pc, piecepos)) {
            when2 = pacing_whenrto(&pc->pacingc, &pc->pacing2[piecepos]);
            if (when2 <= SCHEDULING_TOLERANCE) {
                client_query2(pc, piecepos);
                return 0;
            }
            if (when2 < when) when = when2;
        }
    }

    if (client_query3_isready(pc)) {
        when2 = pacing_whenrto(&pc->pacingc, &pc->pacing3);
        if (when2 <= SCHEDULING_TOLERANCE) {
            client_query3(pc);
            return 0;
        }
        if (when2 < when) when = when2;
    }

    return when;
}

int client_connect(struct client_connection *c, long long timeout) {

    double deadline;
    long long piecepos, rowpos, colpos;
    struct client pc = {0};
    int ret = 0;
    unsigned char h[mc_HASHBYTES];
    unsigned char packet[packet_MAXBYTES + 1];
    unsigned char packetnonce[mc_proto_NONCEBYTES];
    long long packetlen;

    deadline = seconds() + timeout;

    pc.fd = c->fd;
    pc.serveriplen = c->iplen;
    byte_copy(pc.serverip, pc.serveriplen, c->ip);
    byte_copy(pc.serverport, 2, c->port);
    byte_copy(pc.serverpkhash, sizeof pc.serverpkhash, c->serverpkhash);
    byte_copy(pc.serverauthpkhash, sizeof pc.serverauthpkhash,
              c->serverauthpkhash);
    byte_copy(pc.extension, sizeof pc.extension, c->extension);
    byte_copy(&pc.mc, sizeof(struct mc), &c->mc);

    mc_keys_enc(pc.ciphertext, pc.key0, pc.serverpkhash);
    mc_keypair(&pc.mc, h, sizeof h, pc.clientpk, pc.clientsk);

    pacing_connection_init(&pc.pacingc);
    pacing_packet_init(&pc.pacing0, c->mc.mctiny.query0bytes);
    for (rowpos = 0; rowpos < pc.mc.mctiny.rowblocks; ++rowpos) {
        for (colpos = 0; colpos < pc.mc.mctiny.colblocks; ++colpos) {
            pacing_packet_init(&pc.pacing1[rowpos][colpos],
                               c->mc.mctiny.query1bytes);
            pc.flagreply1[rowpos][colpos] = 0;
        }
    }
    for (piecepos = 0; piecepos < pc.mc.mctiny.pieces; ++piecepos) {
        pacing_packet_init(&pc.pacing2[piecepos], c->mc.mctiny.query2bytes);
        pc.flagreply2[piecepos] = 0;
    }
    pacing_packet_init(&pc.pacing3, c->mc.mctiny.query3bytes);

    client_query0_prepare(&pc);

    while (!pc.flagcookie9) {
        double when, whentimeout;
        struct pollfd p[1];
        p[0].fd = pc.fd;
        p[0].events = POLLIN;
        pacing_now_update(&pc.pacingc);

        whentimeout = deadline - seconds();
        if (whentimeout < 0.0) {
            errno = ETIMEDOUT;
            break;
        }

        /* try send */
        for (;;) {
            when = pacing_whendecongested(&pc.pacingc, packet_MAXBYTES);
            if (when > SCHEDULING_TOLERANCE) break;
            when = trytransmitting(&pc, whentimeout);
            if (when > SCHEDULING_TOLERANCE) break;
        }

        if (socket_poll_and_dequeue(p, 1, 1000 * when) <= 0) continue;
        pacing_now_update(&pc.pacingc);

        /* receive packet */
        packetlen = socket_recv(pc.fd, packet, sizeof packet, pc.packetip,
                                pc.packetport);
        log_t2("reply recv, len = ", log_num(packetlen));
        if (packetlen < mc_proto_HEADERBYTES + mc_proto_AUTHBYTES) continue;
        if (packetlen > packet_MAXBYTES) continue;
        byte_copy(packetnonce, packet_NONCEBYTES,
                  packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES);

        if (packetlen == c->mc.mctiny.reply0bytes) {
            if (byte_isequal(packet, mc_proto_MAGICBYTES,
                             mc_proto_MAGICREPLY0)) {
                log_t8("reply0 recv, nonce = ",
                       log_hex(packetnonce, sizeof packetnonce),
                       ", ip = ", log_ip(pc.packetip),
                       ", port = ", log_port(pc.packetport),
                       ", len = ", log_num(packetlen));
                client_reply0(&pc, packet, packetlen);
            }
        }
        if (packetlen == c->mc.mctiny.reply1bytes) {
            if (byte_isequal(packet, mc_proto_MAGICBYTES,
                             mc_proto_MAGICREPLY1)) {
                log_t8("reply1 recv, nonce = ",
                       log_hex(packetnonce, sizeof packetnonce),
                       ", ip = ", log_ip(pc.packetip),
                       ", port = ", log_port(pc.packetport),
                       ", len = ", log_num(packetlen));
                client_reply1(&pc, packet, packetlen);
            }
        }
        if (packetlen == c->mc.mctiny.reply2bytes) {
            if (byte_isequal(packet, mc_proto_MAGICBYTES,
                             mc_proto_MAGICREPLY2)) {
                log_t8("reply2 recv, nonce = ",
                       log_hex(packetnonce, sizeof packetnonce),
                       ", ip = ", log_ip(pc.packetip),
                       ", port = ", log_port(pc.packetport),
                       ", len = ", log_num(packetlen));
                client_reply2(&pc, packet, packetlen);
            }
        }
        if (packetlen == c->mc.mctiny.reply3bytes) {
            if (byte_isequal(packet, mc_proto_MAGICBYTES,
                             mc_proto_MAGICREPLY3)) {
                log_t8("reply3 recv, nonce = ",
                       log_hex(packetnonce, sizeof packetnonce),
                       ", ip = ", log_ip(pc.packetip),
                       ", port = ", log_port(pc.packetport),
                       ", len = ", log_num(packetlen));
                client_reply3(&pc, packet, packetlen);
            }
        }
    }

    /* done */
    ret = pc.flagcookie9;
    if (ret) {
        mc_dec(&pc.mc, pc.key, pc.ciphertext, pc.clientsk);
        mceliece_xof_shake256(pc.key, sizeof pc.key, pc.key, packet_KEYBYTES);
        byte_copy(c->clientkey, packet_KEYBYTES, pc.key);
        byte_copy(c->serverkey, packet_KEYBYTES, pc.key + packet_KEYBYTES);
        c->clientnonce = randommod(281474976710656LL);
        c->servernonce = 0;
        c->receivedtm = 0;
        byte_copy(c->ip, 16, pc.serverip);
        byte_copy(c->port, 2, pc.serverport);
        byte_copy(c->id, 16, pc.longtermnonce);
    }

    byte_zero(&pc, sizeof pc);
    return ret;
}
