#include <randombytes.h>
#include "pacing.h"
#include "mc.h"
#include "socket.h"
#include "seconds.h"
#include "e.h"
#include "log.h"
#include "byte.h"
#include "packet.h"
#include "client_kex.h"

#define SCHEDULING_TOLERANCE 0.001

static double trytransmitting(struct client_kex *c, double when) {

    double when2;
    int flagauth;
    long long pos;

    if (client_kex_query0_isready(c)) {
        for (pos = 0; pos < c->iplen; pos += socket_IPBYTES) {
            when2 = pacing_whenrto(&c->pacingc, &c->pacing0[pos]);
            if (when2 <= SCHEDULING_TOLERANCE) {
                client_kex_query0(c, pos);
                return 0;
            }
            if (when2 < when) when = when2;
        }
    }
    for (flagauth = 0; flagauth < 2; ++flagauth) {
        for (pos = 0; pos < mc_mctiny_BLOCKS; ++pos) {
            if (client_kex_query1_isready(c, pos, flagauth)) {
                when2 = pacing_whenrto(&c->pacingc, &c->pacing1[flagauth][pos]);
                if (when2 <= SCHEDULING_TOLERANCE) {
                    client_kex_query1(c, pos, flagauth);
                    return 0;
                }
                if (when2 < when) when = when2;
            }
        }
    }
    for (flagauth = 0; flagauth < 2; ++flagauth) {
        for (pos = 0; pos < mc_mctiny_PIECES; ++pos) {
            if (client_kex_query2_isready(c, pos, flagauth)) {
                when2 = pacing_whenrto(&c->pacingc, &c->pacing2[flagauth][pos]);
                if (when2 <= SCHEDULING_TOLERANCE) {
                    client_kex_query2(c, pos, flagauth);
                    return 0;
                }
                if (when2 < when) when = when2;
            }
        }
    }
    for (flagauth = 0; flagauth < 2; ++flagauth) {
        for (pos = 0; pos < mc_mctiny_P3PIECES; ++pos) {
            if (client_kex_query3_isready(c, pos, flagauth)) {
                when2 = pacing_whenrto(&c->pacingc, &c->pacing3[flagauth][pos]);
                if (when2 <= SCHEDULING_TOLERANCE) {
                    client_kex_query3(c, pos, flagauth);
                    return 0;
                }
                if (when2 < when) when = when2;
            }
        }
    }
    if (client_kex_query4_isready(c)) {
        when2 = pacing_whenrto(&c->pacingc, &c->pacing4);
        if (when2 <= SCHEDULING_TOLERANCE) {
            client_kex_query4(c);
            return 0;
        }
        if (when2 < when) when = when2;
    }
    return when;
}

static unsigned char zero[mc_HASHBYTES];

int client_kex(int fd, unsigned char *ip, long long iplen, unsigned char *port,
               unsigned char *pkhash, unsigned char *pk,
               unsigned char *extension, unsigned char *authpkhash,
               long long timeout) {
    long long pos, level;
    struct client_kex cli = {0};
    double deadline, starttime = seconds();
    long long packetssent = socket_packetssent();
    long long packetsrecv = socket_packetsreceived();
    int flagauth;

    cli.fd = fd;
    cli.iplen = iplen;
    cli.ip = ip;
    cli.port = port;
    cli.pkhash = pkhash;
    cli.pk = pk;
    cli.extension = extension;

    pacing_connection_init(&cli.pacingc);
    for (pos = 0; pos < cli.iplen; pos += socket_IPBYTES) {
        pacing_packet_init(&cli.pacing0[pos / socket_IPBYTES], packet_MAXBYTES);
    }
    for (flagauth = 0; flagauth < 2; ++flagauth) {
        for (pos = 0; pos < mc_mctiny_BLOCKS; ++pos) {
            pacing_packet_init(&cli.pacing1[flagauth][pos], packet_MAXBYTES);
        }
    }
    for (flagauth = 0; flagauth < 2; ++flagauth) {
        for (pos = 0; pos < mc_mctiny_PIECES; ++pos) {
            pacing_packet_init(&cli.pacing2[flagauth][pos], packet_MAXBYTES);
        }
    }
    for (flagauth = 0; flagauth < 2; ++flagauth) {
        for (pos = 0; pos < mc_mctiny_P3PIECES; ++pos) {
            pacing_packet_init(&cli.pacing3[flagauth][pos], packet_MAXBYTES);
        }
    }
    pacing_packet_init(&cli.pacing4, packet_MAXBYTES);

    if (authpkhash && !byte_isequal(authpkhash, mc_HASHBYTES, zero)) {
        if (!mc_keys_loadpk(cli.authpk, authpkhash)) {
            log_e2("unable to load public-key ",
                   log_hex(authpkhash, mc_HASHBYTES));
            return 0;
        }
        log_d2("key-exchange: authorization public-key hash: ",
               log_hex(authpkhash, mc_HASHBYTES));
        byte_copy(cli.authpkhash, mc_HASHBYTES, authpkhash);
    }
    else {
        mc_keypairf(cli.authpk, cli.authsk);
        mc_pktree_pk2tree(&cli.pktree, cli.authpk);
        log_d2("key-exchange: authorization public-key hash: ",
               log_hex(cli.pktree.l0, mc_HASHBYTES));
        byte_copy(cli.authpkhash, mc_HASHBYTES, cli.pktree.l0);
    }
    mc_enc(cli.ciphertext, cli.key0query, cli.pk);
    mc_derivekeys(cli.key0query, cli.key0reply, cli.key0query);
    mc_keypairf(cli.clientpk, cli.clientsk);
    mc_pktree_pk2tree(&cli.pktree, cli.clientpk);
    log_d2("key-exchange: one-time (fs) public-key hash: ",
           log_hex(cli.pktree.l0, mc_HASHBYTES));

    client_kex_query0_prepare(&cli);

    deadline = seconds() + timeout;

    while (!cli.flagreply4) {

        double when, whentimeout;
        struct pollfd p[1];
        p[0].fd = cli.fd;
        p[0].events = POLLIN;
        pacing_now_update(&cli.pacingc);

        whentimeout = deadline - seconds();
        if (whentimeout < 0.0) {
            errno = ETIMEDOUT;
            return 0;
        }

        /* try send */
        for (;;) {

            when = pacing_whendecongested(&cli.pacingc, packet_MAXBYTES);
            if (when > SCHEDULING_TOLERANCE) {
                log_t3("key-exchange: congested, timeout ",
                       log_num(1000 * when), "ms");
                break;
            }
            when = trytransmitting(&cli, whentimeout);
            if (when > SCHEDULING_TOLERANCE) {
                log_t3("key-exchange: nothing to transmit, timeout ",
                       log_num(1000 * when), "ms");
                break;
            }
        }

        if (socket_poll_and_dequeue(p, 1, 1000.0 * when) <= 0) continue;
        pacing_now_update(&cli.pacingc);

        for (;;) {

            /* receive packet */
            cli.packetlen =
                client_recv(mc_MAGICREPLYK, cli.fd, cli.packet,
                            sizeof cli.packet, cli.packetip, cli.packetport);
            if (cli.packetlen <= 0) break;

            mc_Levpos_load(&level, &pos, &flagauth,
                           cli.packet + mc_MAGICBYTES + mc_EXTENSIONBYTES +
                               mc_NONCEBYTES - 2);

            if (level == 0) {
                if (cli.packetlen != mc_mctiny_REPLYK0BYTES) continue;
                client_kex_reply0(&cli, cli.packet + mc_HEADERBYTES,
                                  cli.packetlen - mc_HEADERBYTES,
                                  cli.packet + mc_MAGICBYTES +
                                      mc_EXTENSIONBYTES);
            }
            if (level == 1) {
                if (cli.packetlen != mc_mctiny_REPLYK1BYTES) continue;
                client_kex_reply1(&cli, cli.packet + mc_HEADERBYTES,
                                  cli.packetlen - mc_HEADERBYTES,
                                  cli.packet + mc_MAGICBYTES +
                                      mc_EXTENSIONBYTES,
                                  pos, flagauth);
            }
            if (level == 2) {
                if (cli.packetlen != mc_mctiny_REPLYK2BYTES) continue;
                client_kex_reply2(&cli, cli.packet + mc_HEADERBYTES,
                                  cli.packetlen - mc_HEADERBYTES,
                                  cli.packet + mc_MAGICBYTES +
                                      mc_EXTENSIONBYTES,
                                  pos, flagauth);
            }
            if (level == 3) {
                if (cli.packetlen != mc_mctiny_REPLYK3BYTES) continue;
                client_kex_reply3(&cli, cli.packet + mc_HEADERBYTES,
                                  cli.packetlen - mc_HEADERBYTES,
                                  cli.packet + mc_MAGICBYTES +
                                      mc_EXTENSIONBYTES,
                                  pos, flagauth);
            }
            if (level == 4) {
                if (cli.packetlen != mc_mctiny_REPLYK4BYTES) continue;
                client_kex_reply4(&cli, cli.packet + mc_HEADERBYTES,
                                  cli.packetlen - mc_HEADERBYTES,
                                  cli.packet + mc_MAGICBYTES +
                                      mc_EXTENSIONBYTES);
            }
        }
    }

    /* key9 */
    mc_dec(cli.key9, cli.ciphertext0, cli.clientsk);
    if (authpkhash && !byte_isequal(authpkhash, mc_HASHBYTES, zero)) {
        mc_keys_dec(cli.key9 + packet_KEYBYTES, cli.ciphertext1, authpkhash);
    }
    else { mc_dec(cli.key9 + packet_KEYBYTES, cli.ciphertext1, cli.authsk); }
    mceliece_xof_shake256(cli.key9, 2 * packet_KEYBYTES, cli.key9,
                          2 * packet_KEYBYTES);
    log_d2("key-exchange: session secret-key identifier: ",
           log_hex(cli.key9 + packet_KEYBYTES, mc_HASHBYTES));

    /* done */
    log_d8(
        "key-exchange: done, time = ", log_num(1000 * (seconds() - starttime)),
        " ms, packets sent = ", log_num(socket_packetssent() - packetssent),
        ", received = ", log_num(socket_packetsreceived() - packetsrecv),
        ", auth = ", log_hex(cli.authpkhash, mc_HASHBYTES));

    return 1;
}
