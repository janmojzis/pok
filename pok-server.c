#include <signal.h>
#include <unistd.h>
#include "randommod.h"
#include "parseport.h"
#include "writeall.h"
#include "parsenum.h"
#include "parseip.h"
#include "seconds.h"
#include "socket.h"
#include "packet.h"
#include "server.h"
#include "byte.h"
#include "open.h"
#include "log.h"
#include "nk.h"
#include "mc.h"

struct activeclient {
    pid_t child;
    int s;
    unsigned char id[16];
};

#define MAXCLIENTS 256
static struct activeclient activeclients[MAXCLIENTS];
static long long numactiveclients = 0;

/*
global buffers
*/
static struct g {
    unsigned char key[2 * packet_KEYBYTES];
    unsigned char packetnonce[packet_NONCEBYTES];
    unsigned char packetextension[mc_EXTENSIONBYTES];
    unsigned char packet[packet_MAXBYTES + 1 + 18];
    long long packetlen;
    unsigned char packetip[16];
    unsigned char packetport[2];
} g;

static char *serveripstr = 0;
static char *serverportstr = 0;
static const char *serverkeydir = 0;
static unsigned char serverip[16];
static unsigned char serverport[2];

static int fdwd = -1;
static int selfpipe[2] = {-1, -1};
static int udpfd = -1;

static struct pollfd p[MAXCLIENTS + 2];

static void die(int x) {
    unsigned char stackspace[4096];
    if (udpfd != -1) {
        socket_close(udpfd);
        udpfd = -1;
    }
    nk_cleanup();
    byte_zero(stackspace, sizeof stackspace);
    byte_zero(&g, sizeof(g));
    byte_zero(activeclients, sizeof(activeclients));
    _exit(x);
}

#define USAGE "usage: pok-server [-vqQr] -k keydir host port prog"

static void usage(void) {
    log_u1(USAGE);
    die(100);
}

static int flagexitasap = 0;
static void signalhandler(int sig) {

    if (sig == SIGCHLD) {
        if (writeall(selfpipe[1], "", 1) == -1) {
            log_f1("unable to write to selfpipe");
            die(111);
        }
        return;
    }
    else { flagexitasap = 1; }
}

static void server_enqueue(int fd, unsigned char *x, long long xlen,
                           unsigned char *ip, unsigned char *port) {

    long long r;
    unsigned char *nonce = x + mc_MAGICBYTES + mc_EXTENSIONBYTES;
    char reply[7] = "replyX";

    if (xlen < mc_HEADERBYTES) return;

    r = socket_enqueue(fd, x, xlen, ip, port);

    reply[5] = x[7];
    log_t9(reply, " send, nonce = ", log_hex(nonce, mc_NONCEBYTES),
           ", ip = ", log_ip(ip), ", port = ", log_port(port),
           ", len = ", log_num(r));
}

static long long server_recv(int fd, unsigned char *x, long long xlen,
                             unsigned char *ip, unsigned char *port) {
    long long r;
    unsigned char *nonce = x + mc_MAGICBYTES + mc_EXTENSIONBYTES;
    char query[7] = "queryX";

    r = socket_recv(fd, x, xlen, ip, port);
    if (r < mc_HEADERBYTES + mc_AUTHBYTES) return -1;
    if (r > packet_MAXBYTES) return -1;
    if (!byte_isequal(g.packet, mc_MAGICBYTES - 1, mc_MAGICQUERY)) return -1;

    query[5] = x[7];
    log_t9(query, " received, nonce = ", log_hex(nonce, mc_NONCEBYTES),
           ", ip = ", log_ip(ip), ", port = ", log_port(port),
           ", len = ", log_num(r));

    return r;
}

int main(int argc, char **argv) {

    char *x;
    double next = 0.0;
    long long i;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, signalhandler);
    signal(SIGCHLD, signalhandler);
    signal(SIGUSR1, log_inc_level);
    signal(SIGUSR2, log_dec_level);

    log_set_name("pok-server");

    /* clang-format off */
    if (argc < 2) usage();
    if (!argv[0]) usage();
    for (;;) {
        if (!argv[1]) break;
        if (argv[1][0] != '-') break;
        x = *++argv;
        if (x[0] == '-' && x[1] == 0) break;
        if (x[0] == '-' && x[1] == '-' && x[2] == 0) break;
        while (*++x) {
            if (*x == 'q') { log_set_level(log_level_USAGE); continue; }
            if (*x == 'Q') { log_set_level(log_level_FATAL); continue; }
            if (*x == 'v') { log_inc_level(/*dummy*/0); continue; }
            if (*x == 'c') { log_set_color(1); continue; }
            if (*x == 'C') { log_set_color(0); continue; }
            if (*x == 'k') {
                if (x[1]) { serverkeydir = x + 1; break; }
                if (argv[1]) { serverkeydir = *++argv; break; }
            }
            usage();
        }
    }
    /* clang-format on */

    serveripstr = *++argv;
    if (!serveripstr) usage();
    serverportstr = *++argv;
    if (!serverportstr) usage();
    if (!*++argv) usage();
    if (!serverkeydir) usage();

    log_set_time(1);
    log_i4("starting pok-server ", serveripstr, " ", serverportstr);

    fdwd = open_cwd();
    if (fdwd == -1) {
        log_f1("unable to open current directory");
        die(111);
    }

    if (open_pipe(selfpipe) == -1) {
        log_f1("unable to create pipe");
        die(111);
    }

    /* ip */
    log_d3("'ip = '", serveripstr, "'");
    if (!parseip(serverip, serveripstr)) {
        log_f3("unable to parse IP '", serveripstr, "'");
        die(111);
    }

    /* port */
    log_d3("'port = '", serverportstr, "'");
    if (!parseport(serverport, serverportstr)) {
        log_f3("unable to parse PORT '", serverportstr, "'");
        die(111);
    }

    udpfd = socket_udp();
    if (udpfd == -1) {
        log_f1("unable to create socket");
        die(111);
    }
    if (socket_bind(udpfd, serverip, serverport) == -1) {
        log_f1("unable to bind socket");
        die(111);
    }

    log_d3("'keydir = '", serverkeydir, "'");
    if (chdir(serverkeydir) == -1) {
        log_f2("unable to change directory to ", serverkeydir);
        die(111);
    }

    while (!flagexitasap) {
        long long timeout = 1000 * (next - seconds());

        log_unset_id();

        if (timeout <= 0) {
            /* cleanup + key rotation */
            unsigned char stackspace[4096];
            /*
            log_t1("keys rotation");
            */
            timeout = 1000 + randommod(1000);
            byte_zero(&g, sizeof(g));
            byte_zero(stackspace, sizeof stackspace);
            nk_next();
            next = seconds() + timeout / 1000;
        }

        for (i = 0; i < numactiveclients; ++i) {
            p[i].fd = activeclients[i].s;
            p[i].events = POLLIN;
        }
        p[numactiveclients].fd = udpfd;
        p[numactiveclients].events = POLLIN;
        p[numactiveclients].revents = 0;
        p[numactiveclients + 1].fd = selfpipe[0];
        p[numactiveclients + 1].events = POLLIN;
        p[numactiveclients + 1].revents = 0;
        if (socket_poll_and_dequeue(p, 2 + numactiveclients, timeout) < 0) {
            continue;
        }

        do {
            if (!(p[numactiveclients].revents & POLLIN)) break;
            g.packetlen = server_recv(udpfd, g.packet, sizeof g.packet,
                                      g.packetip, g.packetport);
            if (g.packetlen < 0) break;

#if 0
            log_set_id_hex((void *) "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16);
#endif

            if (g.packet[7] == 'K') {
                g.packetlen = server_phaseK(g.packet, g.packetlen);
                if (g.packetlen < 0) break;
                server_enqueue(udpfd, g.packet, g.packetlen, g.packetip,
                               g.packetport);
                break;
            }

            if (g.packet[7] == 'L') {
                g.packetlen = server_phaseL(g.packet, g.packetlen);
                if (g.packetlen < 0) break;
                server_enqueue(udpfd, g.packet, g.packetlen, g.packetip,
                               g.packetport);
                break;
            }

        } while (0);
    }
    die(0);
}
