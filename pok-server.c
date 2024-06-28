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

#define MAXCLIENTS 256
static struct server_activeclient activeclients[MAXCLIENTS];
static long long numactiveclients = 0;

/*
global buffers
*/
struct g {
    unsigned char key[2 * packet_KEYBYTES];
    unsigned char packetnonce[packet_NONCEBYTES];
    unsigned char packetextension[mc_proto_EXTENSIONBYTES];
    unsigned char message[message_MAXBYTES + 1];
    long long messagelen;
    unsigned char packet[packet_MAXBYTES + 1];
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

            if (!p[numactiveclients + 1].revents) break;
            read(selfpipe[0], &ch, 1);

            pid = waitpid(-1, &status, WNOHANG);
            if (pid <= 0) break;

            for (i = numactiveclients - 1; i >= 0; --i) {
                if (pid != activeclients[i].child) continue;
                log_set_id_hex(activeclients[i].nonce, 16);
                log_d1("finished connection");
                log_unset_id();
                socket_close(activeclients[i].s);
                --numactiveclients;
                activeclients[i] = activeclients[numactiveclients];
                byte_zero((void *) &activeclients[numactiveclients],
                          sizeof(struct server_activeclient));
                break;
            }
        } while (1);

        do {
            if (!(p[numactiveclients].revents & POLLIN)) break;
            g.packetlen = socket_recv(udpfd, g.packet, sizeof g.packet,
                                      g.packetip, g.packetport);
            if (g.packetlen < 0) break;
            if (g.packetlen < mc_proto_HEADERBYTES + mc_proto_AUTHBYTES) break;
            if (g.packetlen > packet_MAXBYTES) break;
            if (!byte_isequal(g.packet, mc_proto_MAGICBYTES - 1,
                              mc_proto_MAGICQUERY))
                break;
            byte_copy(g.packet, 7, mc_proto_MAGICREPLY);
            byte_copy(g.packetextension, mc_proto_EXTENSIONBYTES,
                      g.packet + mc_proto_MAGICBYTES);
            byte_copy(g.packetnonce, packet_NONCEBYTES,
                      g.packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES);

            log_set_id_hex((void *) "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16);

            if (g.packet[7] == '0') {

                log_t4("query0 recv, nonce = ",
                       log_hex(g.packetnonce, mc_proto_NONCEBYTES),
                       ", len = ", log_num(g.packetlen));
                g.packetlen = server_phase0(g.packet, g.packetlen);
                if (g.packetlen < 0) break;
                g.packetlen = socket_enqueue(udpfd, g.packet, g.packetlen,
                                             g.packetip, g.packetport);
                log_t4("reply0 send, nonce = ",
                       log_hex(g.packet + mc_proto_MAGICBYTES +
                                   mc_proto_EXTENSIONBYTES,
                               mc_proto_NONCEBYTES),
                       ", len = ", log_num(g.packetlen));
                break;
            }

            log_set_id_hex(g.packetnonce, 16);

            if (g.packet[7] == '1') {

                log_t4("query1 recv, nonce = ",
                       log_hex(g.packetnonce, mc_proto_NONCEBYTES),
                       ", len = ", log_num(g.packetlen));
                g.packetlen = server_phase1(g.packet, g.packetlen);
                if (g.packetlen < 0) break;
                g.packetlen = socket_enqueue(udpfd, g.packet, g.packetlen,
                                             g.packetip, g.packetport);
                log_t4("reply1 send, nonce = ",
                       log_hex(g.packet + mc_proto_MAGICBYTES +
                                   mc_proto_EXTENSIONBYTES,
                               mc_proto_NONCEBYTES),
                       ", len = ", log_num(g.packetlen));
                break;
            }

            if (g.packet[7] == '2') {

                log_t4("query2 recv, nonce = ",
                       log_hex(g.packetnonce, mc_proto_NONCEBYTES),
                       ", len = ", log_num(g.packetlen));
                g.packetlen = server_phase2(g.packet, g.packetlen);
                if (g.packetlen < 0) break;

                g.packetlen = socket_enqueue(udpfd, g.packet, g.packetlen,
                                             g.packetip, g.packetport);
                log_t4("reply2 send, nonce = ",
                       log_hex(g.packet + mc_proto_MAGICBYTES +
                                   mc_proto_EXTENSIONBYTES,
                               mc_proto_NONCEBYTES),
                       ", len = ", log_num(g.packetlen));
                break;
            }

            if (g.packet[7] == '3') {

                log_t4("query3 recv, nonce = ",
                       log_hex(g.packetnonce, mc_proto_NONCEBYTES),
                       ", len = ", log_num(g.packetlen));
                g.packetlen = server_phase3(g.key, g.packet, g.packetlen);
                if (g.packetlen < 0) break;

                for (i = 0; i < numactiveclients; ++i) {
                    if (byte_isequal(activeclients[i].nonce, 16, g.packetnonce))
                        break;
                }

                if (i == numactiveclients) {
                    int s[2];

                    if (numactiveclients == MAXCLIENTS) {
                        log_w1("max clients reached");
                        break;
                    }

                    if (socket_pair(s) == -1) {
                        log_f1("socketpair() failed");
                        break;
                    }

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
                        message(s[1], argv, stimeout);
                        die(111);
                    }
                    socket_close(s[1]);

                    activeclients[i].s = s[0];
                    byte_copy(activeclients[i].nonce, 16, g.packetnonce);
                    byte_copy(activeclients[i].clientip, 16, g.packetip);
                    byte_copy(activeclients[i].clientport, 2, g.packetport);
                    byte_copy(activeclients[i].extension, 32,
                              g.packetextension);
                    byte_copy(activeclients[i].clientkey, packet_KEYBYTES,
                              g.key);
                    byte_copy(activeclients[i].serverkey, packet_KEYBYTES,
                              g.key + packet_KEYBYTES);
                    activeclients[i].servernonce = randommod(281474976710656LL);
                    log_d1("starting connection");
                    ++numactiveclients;
                }

                g.packetlen = socket_enqueue(udpfd, g.packet, g.packetlen,
                                             g.packetip, g.packetport);
                log_t4("reply3 send, nonce = ",
                       log_hex(g.packet + mc_proto_MAGICBYTES +
                                   mc_proto_EXTENSIONBYTES,
                               mc_proto_NONCEBYTES),
                       ", len = ", log_num(g.packetlen));
                break;
            }

            if (g.packet[7] == 'M') {

                log_t4("queryM recv, nonce = ",
                       log_hex(g.packetnonce, mc_proto_NONCEBYTES),
                       ", len = ", log_num(g.packetlen));
                if (g.packetlen <
                    (message_HEADERBYTES + mc_proto_HEADERBYTES)) {
                    log_w3("packet len = ", log_num(g.packetlen),
                           ", too short");
                    break;
                }

                for (i = 0; i < numactiveclients; ++i) {
                    if (byte_isequal(activeclients[i].nonce, 16, g.packetnonce))
                        break;
                }

                if (i == numactiveclients) {
                    log_t3("clientid = ", log_hex(g.packetnonce, 16),
                           ", not found");
                }
                if (i >= numactiveclients) break;

                g.messagelen = server_queryM(&activeclients[i], g.message,
                                             g.packet, g.packetlen, g.packetip,
                                             g.packetport, g.packetextension);
                if (g.messagelen < 0) break;
                socket_enqueue(activeclients[i].s, g.message, g.messagelen, 0,
                               0);
                break;
            }

        } while (0);

        for (i = numactiveclients - 1; i >= 0; --i) {
            do {
                if (!(p[i].revents & POLLIN)) break;
                g.messagelen = socket_recv(activeclients[i].s, g.message,
                                           sizeof g.message, 0, 0);
                if (g.messagelen == -1) {
                    if (socket_temperror()) break;
                    /* child is gone */
                    break;
                }
                if (g.messagelen < message_HEADERBYTES) {
                    log_b4("received message too small, messagelen ",
                           log_num(g.messagelen), " < ",
                           log_num(message_HEADERBYTES));
                    break;
                }
                if (g.messagelen > message_MAXBYTES) {
                    log_b4("received message too large, messagelen ",
                           log_num(g.messagelen), " > ",
                           log_num(message_MAXBYTES));
                    break;
                }

                g.packetlen = server_replyM(&activeclients[i], g.packet,
                                            g.message, g.messagelen);
                if (g.packetlen < 0) break;
                g.packetlen = socket_enqueue(udpfd, g.packet, g.packetlen,
                                             activeclients[i].clientip,
                                             activeclients[i].clientport);
                log_t4("replyM send, nonce = ",
                       log_hex(g.packet + mc_proto_MAGICBYTES +
                                   mc_proto_EXTENSIONBYTES,
                               mc_proto_NONCEBYTES),
                       ", len = ", log_num(g.packetlen));
            } while (0);
        }
    }
    die(0);
}
