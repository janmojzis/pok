#include <signal.h>
#include <unistd.h>
#include "log.h"
#include "byte.h"
#include "socket.h"
#include "parseip.h"
#include "parseport.h"
#include "mc.h"

static int fd = -1;
static const char *ipstr = 0;
static const char *portstr = 0;
static unsigned char ip[16];
static unsigned char port[2];

static unsigned char packet[socket_MAXBYTES + 1];
static long long packetlen;
static unsigned char packetip[16];
static unsigned char packetport[2];

static void die(int x) {
    if (fd != -1) {
        close(fd);
        fd = -1;
    }
    _exit(x);
}

#define USAGE "usage: pok-forwarder [-vqQ] IP PORT"
static void usage(void) {
    log_u1(USAGE);
    die(100);
}

static int flagexitasap = 0;
static void exitasap(int sig) {
    log_d3("signal ", log_num(sig), " received");
    flagexitasap = 1;
}

static void swap(unsigned char *x, unsigned char *y) {

    unsigned char t[16];

    byte_copy(t, 16, x);
    byte_copy(x, 16, y);
    byte_copy(y, 16, t);
}

int main(int argc, char **argv) {

    char *x;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, exitasap);
    signal(SIGUSR1, log_inc_level);
    signal(SIGUSR2, log_dec_level);
    log_set_name("pok-forwarder");

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
            usage();
        }
    }
    /* clang-format on */

    ipstr = *++argv;
    if (!ipstr) usage();
    portstr = *++argv;
    if (!portstr) usage();

    log_set_time(1);
    log_i1("starting");

    /* ip */
    log_d3("ip = '", ipstr, "'");
    if (!parseip(ip, ipstr)) {
        log_f3("unable to parse IP '", ipstr, "'");
        die(111);
    }

    /* port */
    log_d3("port = '", portstr, "'");
    if (!parseport(port, portstr)) {
        log_f3("unable to parse PORT '", portstr, "'");
        die(111);
    }

    /* create/bind UDP socket */
    fd = socket_udp();
    if (fd == -1) {
        log_f1("unable to create UDP socket");
        die(111);
    }
    if (socket_bind(fd, ip, port) == -1) {
        log_f5("unable to bind UDP socket, ip = '", log_ip(ip), "', port = '",
               log_port(port), "'");
        die(111);
    }

    while (!flagexitasap) {
        static struct pollfd p[1];

        p[0].fd = fd;
        p[0].events = POLLIN;
        p[0].revents = 0;
        if (socket_poll_and_dequeue(p, 1, -1) < 0) continue;

        do {
            if (!p[0].revents) break;

            packetlen =
                socket_recv(fd, packet, sizeof packet, packetip, packetport);
            if (packetlen < mc_proto_MAGICBYTES + 18) continue;
            if (packetlen > socket_MAXBYTES) continue;

            if (byte_isequal(packet, mc_proto_MAGICBYTES - 1,
                             mc_proto_MAGICQUERY)) {
                swap(packet + mc_proto_MAGICBYTES, packetip);
                byte_copy(packet + mc_proto_MAGICBYTES + 16, 2, packetport);
                byte_copy(packetport, 2, port);
            }
            else if (byte_isequal(packet, mc_proto_MAGICBYTES - 1,
                                  mc_proto_MAGICREPLY)) {
                swap(packet + mc_proto_MAGICBYTES, packetip);
                byte_copy(packetport, 2, packet + mc_proto_MAGICBYTES + 16);
                byte_zero(packet + mc_proto_MAGICBYTES + 16, 2);
            }
            else { continue; }

            socket_enqueue(fd, packet, packetlen, packetip, packetport);

        } while (0);
    }

    log_i1("finished");
    die(0);
}
