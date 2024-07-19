#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "nk.h"
#include "seconds.h"
#include "byte.h"
#include "open.h"
#include "randommod.h"
#include "server.h"
#include "message.h"
#include "parseip.h"
#include "parsenum.h"
#include "parseport.h"
#include "blocking.h"
#include "writeall.h"
#include "packet.h"
#include "socket.h"
#include "mc.h"

#include <string.h>

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
struct g {
    unsigned char key[2 * packet_KEYBYTES];
    unsigned char packetnonce[packet_NONCEBYTES];
    unsigned char packetextension[mc_proto_EXTENSIONBYTES];
    unsigned char packet[packet_MAXBYTES + 1 + 18];
    long long packetlen;
    unsigned char packetip[16];
    unsigned char packetport[2];
} g;

static const char *serverkeydir = 0;
static unsigned char serverip[16];
static unsigned char serverport[2];

static int fdwd = -1;
static int selfpipe[2] = {-1, -1};
static int udpfd = -1;
static const char *stimeoutstr = "300";
static long long stimeout;

static struct pollfd p[MAXCLIENTS + 2];

static char *servername = 0;
static char *serverportstr = 0;

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
    unsigned char *nonce = x + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES;
    char reply[7] = "replyX";

    if (xlen < mc_proto_HEADERBYTES) return;

    r = socket_enqueue(fd, x, xlen, ip, port);

    reply[5] = x[7];
    log_t9(reply, " send, nonce = ", log_hex(nonce, mc_proto_NONCEBYTES),
           ", ip = ", log_ip(ip), ", port = ", log_port(port),
           ", len = ", log_num(r));
}

static long long server_recv(int fd, unsigned char *x, long long xlen,
                             unsigned char *ip, unsigned char *port) {
    long long r;
    unsigned char *nonce = x + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES;
    char query[7] = "queryX";

    r = socket_recv(fd, x, xlen, ip, port);
    if (r < mc_proto_HEADERBYTES + mc_proto_AUTHBYTES) return -1;
    if (r > packet_MAXBYTES) return -1;
    if (!byte_isequal(g.packet, mc_proto_MAGICBYTES - 1, mc_proto_MAGICQUERY))
        return -1;

    query[5] = x[7];
    log_t9(query, " received, nonce = ", log_hex(nonce, mc_proto_NONCEBYTES),
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
            if (*x == 't') {
                if (x[1]) { stimeoutstr = x + 1; break; }
                if (argv[1]) { stimeoutstr = *++argv; break; }
            }
            usage();
        }
    }
    /* clang-format on */

    servername = *++argv;
    if (!servername) usage();
    serverportstr = *++argv;
    if (!serverportstr) usage();
    if (!*++argv) usage();
    if (!serverkeydir) usage();

    log_set_time(1);
    log_i4("starting pok-server ", servername, " ", serverportstr);

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
    log_d3("'ip = '", servername, "'");
    if (!parseip(serverip, servername)) {
        log_f3("unable to parse IP '", servername, "'");
        die(111);
    }

    /* port */
    log_d3("'port = '", serverportstr, "'");
    if (!parseport(serverport, serverportstr)) {
        log_f3("unable to parse PORT '", serverportstr, "'");
        die(111);
    }

    /* session-timeout */
    log_d3("session-timeout = '", stimeoutstr, "'");
    if (!parsenum(&stimeout, 1, 3600, stimeoutstr)) {
        log_f3("unable to parse -t session-timeout string '", stimeoutstr, "'");
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

    if (chdir(serverkeydir) == -1) {
        log_f2("unable to change directory to ", serverkeydir);
        die(111);
    }
    if (chdir("server") == -1) {
        log_f3("unable to change directory to ", serverkeydir, "/server");
        die(111);
    }

    while (!flagexitasap) {
        long long timeout = 1000 * (next - seconds());

        log_unset_id();

        if (timeout <= 0) {
            /* cleanup + key rotation */
            unsigned char stackspace[4096];
            log_t1("keys rotation");
            timeout = 30000;
            timeout += randommod(1000);
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
        if (socket_poll_and_dequeue(p, 2 + numactiveclients, timeout) < 0)
            continue;

        do { /* endconnection */
            char ch;
            int status;
            pid_t pid;
            long long dummy;

            if (!p[numactiveclients + 1].revents) break;
            dummy = read(selfpipe[0], &ch, 1);
            (void) dummy;

            pid = waitpid(-1, &status, WNOHANG);
            if (pid <= 0) break;

            for (i = numactiveclients - 1; i >= 0; --i) {
                if (pid != activeclients[i].child) continue;
                log_set_id_hex(activeclients[i].id, 16);
                log_d1("finished connection");
                log_unset_id();
                socket_close(activeclients[i].s);
                --numactiveclients;
                activeclients[i] = activeclients[numactiveclients];
                byte_zero(&activeclients[numactiveclients],
                          sizeof(struct activeclient));
                break;
            }
        } while (1);

        do {
            if (!(p[numactiveclients].revents & POLLIN)) break;
            g.packetlen = server_recv(udpfd, g.packet, sizeof g.packet,
                                      g.packetip, g.packetport);
            if (g.packetlen < 0) break;

            byte_copy(g.packet, 7, mc_proto_MAGICREPLY);
            byte_copy(g.packetextension, mc_proto_EXTENSIONBYTES,
                      g.packet + mc_proto_MAGICBYTES);
            byte_copy(g.packetnonce, packet_NONCEBYTES,
                      g.packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES);

            log_set_id_hex((void *) "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16);

            if (g.packet[7] == '0') {
                g.packetlen = server_phase0(g.packet, g.packetlen);
                if (g.packetlen < 0) break;
                server_enqueue(udpfd, g.packet, g.packetlen, g.packetip,
                               g.packetport);
                break;
            }

            log_set_id_hex(g.packetnonce, 16);

            if (g.packet[7] == '1') {
                g.packetlen = server_phase1(g.packet, g.packetlen);
                if (g.packetlen < 0) break;
                server_enqueue(udpfd, g.packet, g.packetlen, g.packetip,
                               g.packetport);
                break;
            }

            if (g.packet[7] == '2') {
                g.packetlen = server_phase2(g.packet, g.packetlen);
                if (g.packetlen < 0) break;

                server_enqueue(udpfd, g.packet, g.packetlen, g.packetip,
                               g.packetport);
                break;
            }

            if (g.packet[7] == '3') {
                g.packetlen = server_phase3(g.key, g.packet, g.packetlen);
                if (g.packetlen < 0) break;

                for (i = 0; i < numactiveclients; ++i) {
                    if (byte_isequal(activeclients[i].id, 16, g.packetnonce))
                        break;
                }

                if (i == numactiveclients) {
                    int s[2];

                    if (numactiveclients == MAXCLIENTS) {
                        log_w1("max clients reached");
                        break;
                    }

                    if (socket_pair(s) == -1) {
                        log_f1("socket_pair() failed");
                        break;
                    }

                    log_d1("starting connection");

                    activeclients[i].child = fork();
                    if (activeclients[i].child == -1) {
                        log_f1("fork() failed");
                        socket_close(s[0]);
                        socket_close(s[1]);
                        break;
                    }

                    if (activeclients[i].child == 0) {
                        if (fchdir(fdwd) == -1) {
                            log_f1("unable to chdir to original directory");
                            die(111);
                        }
                        socket_close(s[0]);
                        signal(SIGPIPE, SIG_DFL);
                        signal(SIGCHLD, SIG_DFL);
                        signal(SIGTERM, SIG_DFL);
                        signal(SIGUSR1, SIG_DFL);
                        signal(SIGUSR2, SIG_DFL);
                        server_child(g.packetip, g.packetport, g.packetnonce,
                                     g.packetextension, g.key, s[1], argv,
                                     stimeout);
                        die(111);
                    }
                    socket_close(s[1]);

                    byte_copy(activeclients[i].id, 16, g.packetnonce);
                    activeclients[i].s = s[0];
                    ++numactiveclients;
                }

                server_enqueue(udpfd, g.packet, g.packetlen, g.packetip,
                               g.packetport);
                break;
            }

            if (g.packet[7] == 'M') {
                if (g.packetlen <
                    (message_HEADERBYTES + mc_proto_HEADERBYTES)) {
                    log_w3("packet len = ", log_num(g.packetlen),
                           ", too short");
                    break;
                }

                for (i = 0; i < numactiveclients; ++i) {
                    if (byte_isequal(activeclients[i].id, 16, g.packetnonce))
                        break;
                }

                if (i == numactiveclients) {
                    log_t3("clientid = ", log_hex(g.packetnonce, 16),
                           ", not found");
                }
                if (i >= numactiveclients) break;

                /* XXX */
                memmove(g.packet + 18, g.packet, g.packetlen);
                byte_copy(g.packet, 16, g.packetip);
                byte_copy(g.packet + 16, 2, g.packetport);

                socket_enqueue(activeclients[i].s, g.packet, g.packetlen + 18,
                               0, 0);
                break;
            }

        } while (0);

        for (i = numactiveclients - 1; i >= 0; --i) {
            do {
                if (!(p[i].revents & POLLIN)) break;
                g.packetlen = socket_recv(activeclients[i].s, g.packet,
                                          sizeof g.packet, 0, 0);
                if (g.packetlen == -1) {
                    if (socket_temperror()) break;
                    /* child is gone */
                    break;
                }
                if (g.packetlen - 18 <
                    (message_HEADERBYTES + mc_proto_HEADERBYTES)) {
                    log_w4("received packet too small, packetlen ",
                           log_num(g.packetlen), " < ",
                           log_num(message_HEADERBYTES + mc_proto_HEADERBYTES));
                    break;
                }
                if (g.packetlen - 18 > packet_MAXBYTES) {
                    log_w4("received packet too large, packetlen ",
                           log_num(g.packetlen), " > ",
                           log_num(packet_MAXBYTES));
                    break;
                }

                byte_copy(g.packetip, 16, g.packet);
                byte_copy(g.packetport, 2, g.packet + 16);
                byte_copy(g.packet, g.packetlen - 18, g.packet + 18);
                g.packetlen -= 18;

                server_enqueue(udpfd, g.packet, g.packetlen, g.packetip,
                               g.packetport);
            } while (0);
        }
    }
    die(0);
}
