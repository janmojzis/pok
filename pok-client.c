#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <poll.h>
#include <errno.h>
#include "log.h"
#include "byte.h"
#include "resolvehost.h"
#include "open.h"
#include "socket.h"
#include "seconds.h"
#include "message.h"
#include "uint64_pack.h"
#include "uint64_unpack.h"
#include "packet.h"
#include "mc.h"
#include "parsenum.h"
#include "parseport.h"
#include "extension.h"
#include "socket.h"
#include "client.h"

static const char *ktimeoutstr = "60";
static long long ktimeout;
static const char *stimeoutstr = "300";
static long long stimeout;
static const char *extensionstr = "";
static const char *hoststr = 0;
static const char *portstr = 0;
static const char *keydir = 0;
static const char *prog = 0;
static const char *alg = "mceliece6688128";
static int fdwd = -1;
static int s[2] = {-1, -1};
static pid_t child = -1;
static int childstatus;

static struct client_connection c = {0};
static unsigned char packetip[16];
static unsigned char packetport[2];
static unsigned char packet[packet_MAXBYTES + 1];
static long long packetlen;
static unsigned char *packetnonce =
    packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES;

static struct g {
    unsigned char message[message_MAXBYTES + 1];
    long long messagelen;
} g;

static void die(int x) {
    byte_zero(&g, sizeof g);
    byte_zero(&c, sizeof c);
    _exit(x);
}

#define USAGE                                                                  \
    "usage: pok-client [-vqQ] [-t session-timeout] [-T kex-timeout] "          \
    " [-m mcelieceXXXXYYY] -k keydir host port [prog]"

static void usage(void) {
    log_u1(USAGE);
    die(100);
}

static void exitasap(int sig) {
    log_d3("signal ", log_num(sig), " received");
    die(111);
}

static void exitalarm(int sig) {
    log_d3("signal ", log_num(sig), " received");
    alarm(1); /* XXX */
}

int main(int argc, char **argv) {

    char *x;
    long long r;
    double starttime = seconds();

    signal(SIGTERM, exitasap);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGUSR1, log_inc_level);
    signal(SIGUSR2, log_dec_level);

    log_set_name("pok-client");

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
            if (*x == 'T') {
                if (x[1]) { ktimeoutstr = x + 1; break; }
                if (argv[1]) { ktimeoutstr = *++argv; break; }
            }
            if (*x == 't') {
                if (x[1]) { stimeoutstr = x + 1; break; }
                if (argv[1]) { stimeoutstr = *++argv; break; }
            }
            if (*x == 'k') {
                if (x[1]) { keydir = x + 1; break; }
                if (argv[1]) { keydir = *++argv; break; }
            }
            if (*x == 'e') {
                if (x[1]) { extensionstr = x + 1; break; }
                if (argv[1]) { extensionstr = *++argv; break; }
            }
            if (*x == 'm') {
                if (x[1]) { alg = x + 1; break; }
                if (argv[1]) { alg = *++argv; break; }
            }
            usage();
        }
    }
    /* clang-format on */

    hoststr = *++argv;
    if (!hoststr) usage();
    portstr = *++argv;
    if (!portstr) usage();
    prog = *++argv;
    if (!keydir) usage();

    log_set_time(1);
    log_i1("starting");

    /* resolve host */
    log_d3("host = '", hoststr, "'");
    c.iplen = resolvehost(c.ip, sizeof c.ip, hoststr);
    if (c.iplen <= 0) {
        const char *why = 0;
        if (c.iplen == 0) why = ": host not found";
        log_f4("unable to resolve host '", hoststr, "'", why);
        die(111);
    }

    /* port */
    log_d3("port = '", portstr, "'");
    if (!parseport(c.port, portstr)) {
        log_f3("unable to parse port '", portstr, "'");
        die(111);
    }

    /* kex-timeout */
    log_d3("kex-timeout = '", ktimeoutstr, "'");
    if (!parsenum(&ktimeout, 1, 3600, ktimeoutstr)) {
        log_f3("unable to parse -T kex-timeout string '", ktimeoutstr, "'");
        die(111);
    }

    /* session-timeout */
    log_d3("session-timeout = '", stimeoutstr, "'");
    if (!parsenum(&stimeout, 1, 3600, stimeoutstr)) {
        log_f3("unable to parse -t session-timeout string '", stimeoutstr, "'");
        die(111);
    }

    /* extension */
    log_d3("extension = '", extensionstr, "'");
    if (!extension_parse(c.extension, extensionstr)) {
        log_f3("unable to parse -e extension string '", extensionstr, "'");
        die(111);
    }

    /* mceliece variant */
    log_d3("short-term (mctiny) algorithm = '", alg, "'");
    if (!mc_parse(&c.mc, alg)) {
        log_f3("unable to parse -m mcelieceXXXXYYY string '", alg, "'");
        die(111);
    }

    /* keydir */
    fdwd = open_cwd();
    if (fdwd == -1) {
        log_f1("unable to open current directory");
        die(111);
    }
    log_d3("keydir = '", keydir, "'");
    if (chdir(keydir) == -1) {
        log_f2("unable to change directory to ", keydir);
        die(111);
    }
    if (chdir("client") == -1) {
        log_f3("unable to change directory to ", keydir, "/client");
        die(111);
    }
    log_d5("host keydir = '", keydir, "/client/", hoststr, "'");
    if (chdir(hoststr) == -1) {
        log_f4("unable to change directory to ", keydir, "/client/", hoststr);
        die(111);
    }

    if (!mc_keys(c.serverpkhash, sizeof c.serverpkhash, "remote")) {
        log_f3("unable to load ", hoststr, " public-keys");
        die(111);
    }
    log_d6("long-term host public-key loaded from ", keydir, "/client/",
           hoststr, "/remote/", log_hex(c.serverpkhash, sizeof c.serverpkhash));

    if (!mc_keys(c.serverauthpkhash, sizeof c.serverauthpkhash, "public")) {
        log_d5("authorization not requested, no public-key readed from ",
               keydir, "/client/", hoststr, "/public/");
    }
    else {
        log_d6("authorization requested, public-key loaded from ", keydir,
               "/client/", hoststr, "/public/",
               log_hex(c.serverauthpkhash, sizeof c.serverauthpkhash));
    }

    c.fd = socket_udp();
    if (c.fd == -1) {
        log_f1("unable to create UDP socket");
        die(111);
    }

    if (!client_connect(&c, ktimeout)) {
        log_f5("unable to connect, host = '", hoststr, "', port = '", portstr,
               "'");
        die(111);
    }
    log_i9(c.mc.name, " key-exchange done, time = ",
           log_num(1000 * (seconds() - starttime)),
           " ms, packets sent = ", log_num(socket_packetssent()),
           ", received = ", log_num(socket_packetsreceived()),
           ", id = ", log_hex(c.id, 16));

    if (fchdir(fdwd) == -1) {
        log_f1("unable to change directory to original directory");
        die(111);
    }

    if (socket_pair(s) == -1) {
        log_f1("unable to create socketpair");
        die(111);
    }

    child = fork();
    if (child == -1) {
        log_f1("unable to fork");
        die(111);
    }
    if (child == 0) {
        signal(SIGHUP, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);
        signal(SIGALRM, SIG_DFL);
        signal(SIGPIPE, SIG_DFL);
        signal(SIGUSR1, SIG_DFL);
        signal(SIGUSR2, SIG_DFL);
        close(s[0]);
        message(s[1], argv, stimeout);
    }
    close(s[1]);

    signal(SIGHUP, exitalarm);
    signal(SIGTERM, exitalarm);
    signal(SIGCHLD, exitalarm);
    signal(SIGALRM, exitasap);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGUSR1, log_inc_level);
    signal(SIGUSR2, log_dec_level);

    for (;;) {
        struct pollfd p[2];
        p[0].fd = c.fd;
        p[0].events = POLLIN;
        p[1].fd = s[0];
        p[1].events = POLLIN;
        p[1].revents = 0;

        if (socket_poll_and_dequeue(p, 2, -1) < 0) {
            p[0].revents = 0;
            p[1].revents = 0;
        }

        do { /* try receiving a Message packet: */
            if (!p[0].revents) break;
            packetlen =
                socket_recv(c.fd, packet, sizeof packet, packetip, packetport);
            if (packetlen < mc_proto_HEADERBYTES + mc_proto_AUTHBYTES) break;
            if (packetlen > packet_MAXBYTES) break;
            if (!byte_isequal(packet, mc_proto_MAGICBYTES,
                              mc_proto_MAGICREPLYM))
                break;
            if (!byte_isequal(packetnonce, 16, c.id)) break;

            log_t8("replyM recv, nonce = ",
                   log_hex(packetnonce, mc_proto_NONCEBYTES),
                   ", ip = ", log_ip(packetip),
                   ", port = ", log_port(packetport),
                   ", len = ", log_num(packetlen));

            g.messagelen = client_replyM(&c, g.message, packet, packetlen);
            if (g.messagelen < message_HEADERBYTES) break;

            if (socket_enqueue(s[0], g.message, g.messagelen, 0, 0) < 0) {
                if (socket_temperror()) {
                    errno = 0;
                    break;
                }
                goto done;
            }

        } while (1);

        do { /* try receiving message from child: */
            if (!p[1].revents) break;
            g.messagelen = socket_recv(s[0], g.message, sizeof g.message, 0, 0);
            if (g.messagelen == -1) {
                if (socket_temperror()) {
                    errno = 0;
                    break;
                }
                /* child is gone */
                goto done;
            }
            if (g.messagelen < message_HEADERBYTES) {
                log_b4("received message too small, messagelen ",
                       log_num(g.messagelen), " < ",
                       log_num(message_HEADERBYTES));
                goto done;
            }
            if (g.messagelen > message_MAXBYTES) {
                log_b4("received message too large, messagelen ",
                       log_num(g.messagelen), " > ", log_num(message_MAXBYTES));
                goto done;
            }

            client_queryM(&c, g.message, g.messagelen);
        } while (1);
    }

done:

    close(s[0]);
    do {
        r = waitpid(child, &childstatus, 0);
    } while (r == -1 && errno == EINTR);

    if (!WIFEXITED(childstatus)) {
        errno = 0;
        log_f2("process killed by signal ", log_num(WTERMSIG(childstatus)));
        die(111);
    }
    log_i6("finished, time = ", log_num(1000 * (seconds() - starttime)),
           " ms, packets sent = ", log_num(socket_packetssent()),
           ", received = ", log_num(socket_packetsreceived()));
    die(childstatus);
}
