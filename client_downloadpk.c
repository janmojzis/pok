#include "pacing.h"
#include "mc.h"
#include "socket.h"
#include "seconds.h"
#include "e.h"
#include "log.h"
#include "byte.h"
#include "packet.h"
#include "client.h"

#define SCHEDULING_TOLERANCE 0.001

struct cli {
    struct mc_pktree *pktree;

    struct pacing_connection pacingc;
    struct pacing_packet pacing1[client_NUMIP];
    struct pacing_packet pacing2[mc_pktree_L2BLOCKS];
    struct pacing_packet pacing3[mc_pktree_L3BLOCKS];
    struct pacing_packet pacing4[mc_pktree_L4BLOCKS];
    int flagreply1;
    int flagreply2[mc_pktree_L2BLOCKS];
    int flagreply3[mc_pktree_L3BLOCKS];
    int flagreply4[mc_pktree_L4BLOCKS];
    long long reply4count;

    unsigned char *pkhash;
    unsigned char *extension;
    int fd;
    unsigned char *ip;
    long long iplen;
    unsigned char *port;

    unsigned char packet[packet_MAXBYTES + 1];
    unsigned char packetip[socket_IPBYTES];
    unsigned char packetport[socket_PORTBYTES];
    long long packetlen;
};

static void query(struct cli *c, long long level, long long pos) {
    byte_zero(c->packet, packet_MAXBYTES);
    byte_copy(c->packet, mc_MAGICBYTES, mc_MAGICQUERYL);
    byte_copy(c->packet + mc_MAGICBYTES, mc_EXTENSIONBYTES, c->extension);

    mc_Levpos_store(c->packet + mc_MAGICBYTES + mc_EXTENSIONBYTES, level, pos,
                    0);
    byte_copy(c->packet + mc_MAGICBYTES + mc_EXTENSIONBYTES + 2, mc_HASHBYTES,
              c->pkhash);
}

static int query1_isready(struct cli *c) { return !c->flagreply1; }

static void query1(struct cli *c, long long ippos) {

    if (!query1_isready(c)) return;
    query(c, 1, 0);

    client_send(c->fd, c->packet, packet_MAXBYTES, c->ip + ippos, c->port);
    pacing_transmitted(&c->pacingc, &c->pacing1[ippos / socket_IPBYTES]);
}

static void reply1(struct cli *c) {

    long long i;

    if (!query1_isready(c)) { return; }
    if (!mc_pktree_block_put(c->pktree, 0, 0, c->pkhash, mc_HASHBYTES)) {
        log_w1("key-download: dropping reply1, malformed packet");
        return;
    }
    if (!mc_pktree_block_put(
            c->pktree, 1, 0, c->packet + mc_MAGICBYTES + mc_EXTENSIONBYTES + 2,
            c->packetlen - mc_MAGICBYTES - mc_EXTENSIONBYTES - 2)) {
        log_w1("key-download: dropping reply1, malformed packet");
        return;
    }
    for (i = 0; i < c->iplen; i += socket_IPBYTES) {
        if (byte_isequal(c->packetip, socket_IPBYTES, c->ip + i)) {
            byte_swap(c->ip, socket_IPBYTES, c->ip + i);
            break;
        }
    }
    for (i = 0; i < c->iplen; i += socket_IPBYTES) {
        pacing_acknowledged(&c->pacingc, &c->pacing1[i / socket_IPBYTES]);
    }
    c->flagreply1 = 1;
}

static int query2_isready(struct cli *c, long long pos) {
    if (!c->flagreply1) return 0;
    if (c->flagreply2[pos]) return 0;
    return 1;
}

static void query2(struct cli *c, long long pos) {

    if (!query2_isready(c, pos)) { return; }
    query(c, 2, pos);

    client_send(c->fd, c->packet, packet_MAXBYTES, c->ip, c->port);
    pacing_transmitted(&c->pacingc, &c->pacing2[pos]);
}

static void reply2(struct cli *c, long long pos) {

    if (!query2_isready(c, pos)) { return; }
    if (!mc_pktree_block_put(c->pktree, 2, pos,
                             c->packet + mc_MAGICBYTES + mc_EXTENSIONBYTES + 2,
                             c->packetlen - mc_MAGICBYTES - mc_EXTENSIONBYTES -
                                 2)) {
        log_w3("key-download: dropping reply2/", log_num(pos),
               ", malformed packet");
        return;
    }
    pacing_acknowledged(&c->pacingc, &c->pacing2[pos]);
    c->flagreply2[pos] = 1;
}

static int query3_isready(struct cli *c, long long pos) {
    long long l2pos = (pos * mc_HASHBYTES) / mc_pktree_L2BLOCKBYTES;
    if (!c->flagreply2[l2pos]) return 0;
    if (c->flagreply3[pos]) return 0;
    return 1;
}

static void query3(struct cli *c, long long pos) {

    if (!query3_isready(c, pos)) return;

    query(c, 3, pos);

    client_send(c->fd, c->packet, packet_MAXBYTES, c->ip, c->port);
    pacing_transmitted(&c->pacingc, &c->pacing3[pos]);
}

static void reply3(struct cli *c, long long pos) {

    if (!query3_isready(c, pos)) { return; }

    if (!mc_pktree_block_put(c->pktree, 3, pos,
                             c->packet + mc_MAGICBYTES + mc_EXTENSIONBYTES + 2,
                             c->packetlen - mc_MAGICBYTES - mc_EXTENSIONBYTES -
                                 2)) {
        log_w3("key-download: dropping reply3/", log_num(pos),
               ", malformed packet");
        return;
    }
    pacing_acknowledged(&c->pacingc, &c->pacing3[pos]);
    c->flagreply3[pos] = 1;
}

static int query4_isready(struct cli *c, long long pos) {
    long long l3pos = (pos * mc_HASHBYTES) / mc_pktree_L3BLOCKBYTES;
    if (!c->flagreply3[l3pos]) return 0;
    if (c->flagreply4[pos]) return 0;
    return 1;
}

static void query4(struct cli *c, long long pos) {

    if (!query4_isready(c, pos)) return;
    query(c, 4, pos);

    client_send(c->fd, c->packet, packet_MAXBYTES, c->ip, c->port);
    pacing_transmitted(&c->pacingc, &c->pacing4[pos]);
}

static void reply4(struct cli *c, long long pos) {

    if (!query4_isready(c, pos)) { return; }

    if (!mc_pktree_block_put(c->pktree, 4, pos,
                             c->packet + mc_MAGICBYTES + mc_EXTENSIONBYTES + 2,
                             c->packetlen - mc_MAGICBYTES - mc_EXTENSIONBYTES -
                                 2)) {
        log_w3("key-download: dropping reply4/", log_num(pos),
               ", malformed packet");
        return;
    }
    pacing_acknowledged(&c->pacingc, &c->pacing4[pos]);
    c->flagreply4[pos] = 1;
    ++c->reply4count;
}

static double trytransmitting(struct cli *c, double when) {

    double when2;
    long long pos;

    if (query1_isready(c)) {
        for (pos = 0; pos < c->iplen; pos += socket_IPBYTES) {
            when2 = pacing_whenrto(&c->pacingc, &c->pacing1[pos]);
            if (when2 <= SCHEDULING_TOLERANCE) {
                query1(c, pos);
                return 0;
            }
            if (when2 < when) when = when2;
        }
    }
    for (pos = 0; pos < mc_pktree_L2BLOCKS; ++pos) {
        if (query2_isready(c, pos)) {
            when2 = pacing_whenrto(&c->pacingc, &c->pacing2[pos]);
            if (when2 <= SCHEDULING_TOLERANCE) {
                query2(c, pos);
                return 0;
            }
            if (when2 < when) when = when2;
        }
    }
    for (pos = 0; pos < mc_pktree_L3BLOCKS; ++pos) {
        if (query3_isready(c, pos)) {
            when2 = pacing_whenrto(&c->pacingc, &c->pacing3[pos]);
            if (when2 <= SCHEDULING_TOLERANCE) {
                query3(c, pos);
                return 0;
            }
            if (when2 < when) when = when2;
        }
    }
    for (pos = 0; pos < mc_pktree_L4BLOCKS; ++pos) {
        if (query4_isready(c, pos)) {
            when2 = pacing_whenrto(&c->pacingc, &c->pacing4[pos]);
            if (when2 <= SCHEDULING_TOLERANCE) {
                query4(c, pos);
                return 0;
            }
            if (when2 < when) when = when2;
        }
    }
    return when;
}

int client_downloadpk(struct mc_pktree *pktree, int fd, unsigned char *ip,
                      long long iplen, unsigned char *port,
                      unsigned char *extension, unsigned char *pkhash,
                      long long timeout) {

    long long pos, level;
    struct cli cli = {0};
    double deadline, starttime = seconds();
    long long packetssent = socket_packetssent();
    long long packetsrecv = socket_packetsreceived();

    cli.pktree = pktree;
    cli.fd = fd;
    cli.iplen = iplen;
    cli.ip = ip;
    cli.port = port;
    cli.pkhash = pkhash;
    cli.extension = extension;

    pacing_connection_init(&cli.pacingc);
    for (pos = 0; pos < cli.iplen; pos += socket_IPBYTES) {
        pacing_packet_init(&cli.pacing1[pos / socket_IPBYTES], packet_MAXBYTES);
    }
    for (pos = 0; pos < mc_pktree_L2BLOCKS; ++pos) {
        pacing_packet_init(&cli.pacing2[pos], packet_MAXBYTES);
    }
    for (pos = 0; pos < mc_pktree_L3BLOCKS; ++pos) {
        pacing_packet_init(&cli.pacing3[pos], packet_MAXBYTES);
    }
    for (pos = 0; pos < mc_pktree_L4BLOCKS; ++pos) {
        pacing_packet_init(&cli.pacing4[pos], packet_MAXBYTES);
    }

    deadline = seconds() + timeout;

    while (cli.reply4count != mc_pktree_L4BLOCKS) {

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
                log_t3("key-download: congested, timeout ",
                       log_num(1000 * when), "ms");
                break;
            }
            when = trytransmitting(&cli, whentimeout);
            if (when > SCHEDULING_TOLERANCE) {
                log_t3("key-download: nothing to transmit, timeout ",
                       log_num(1000 * when), "ms");
                break;
            }
        }

        if (socket_poll_and_dequeue(p, 1, 1000 * when) <= 0) continue;
        pacing_now_update(&cli.pacingc);

        for (;;) {

            /* receive packet */
            cli.packetlen =
                client_recv(mc_MAGICREPLYL, cli.fd, cli.packet,
                            sizeof cli.packet, cli.packetip, cli.packetport);
            if (cli.packetlen <= 0) break;

            mc_Levpos_load(&level, &pos, 0,
                           cli.packet + mc_MAGICBYTES + mc_EXTENSIONBYTES);

            if (level < 1 || level > 4) {
                log_w2("key-download: dropping packet, bad level ",
                       log_num(level));
                break;
            }

            log_t8("key-download: reply", log_num(level), "/", log_num0(pos, 3),
                   " recv ", log_ipport(cli.packetip, cli.packetport),
                   ", len = ", log_num(cli.packetlen));

            if (level == 1) { reply1(&cli); }
            if (level == 2) { reply2(&cli, pos); }
            if (level == 3) { reply3(&cli, pos); }
            if (level == 4) { reply4(&cli, pos); }
        }
    }

    log_d8(
        "key-download: done, time = ", log_num(1000 * (seconds() - starttime)),
        " ms, packets sent = ", log_num(socket_packetssent() - packetssent),
        ", received = ", log_num(socket_packetsreceived() - packetsrecv),
        ", hash = ", log_hex(cli.pktree->l0, mc_HASHBYTES));

    return 1;
}
