#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <poll.h>
#include "e.h"
#include "log.h"
#include "byte.h"
#include "resolvehost.h"
#include "resolvetxtkeys.h"
#include "open.h"
#include "socket.h"
#include "seconds.h"
#include "packet.h"
#include "parsenum.h"
#include "parseport.h"
#include "parsehex.h"
#include "socket.h"
#include "mc.h"
#include "client.h"

static const char *ktimeoutstr = "120";
static long long ktimeout;
static const char *stimeoutstr = "300";
static long long stimeout;
static const char *hoststr = 0;
static const char *portstr = 0;
static const char *keydir = 0;
static const char *prog = 0;
static int fdwd = -1;
static int udpfd = -1;

static char *authpkhashstr = 0;
static unsigned char authpkhash[mc_HASHBYTES] = {0};
static char *serverpkhashstr = 0;
static unsigned char serverip[client_NUMIP * socket_IPBYTES];
static unsigned char serverport[socket_PORTBYTES];
static unsigned char serverpk[mc_PUBLICKEYBYTES];
static unsigned char serverpkhash[mc_HASHBYTES];
static unsigned char serverextension[mc_EXTENSIONBYTES];
static long long serveriplen;
static struct mc_pktree serverpktree;

#if 0
static int s[2] = {-1, -1};
static pid_t child = -1;
#endif
static int childstatus;

#if 0
static unsigned char packetip[16];
static unsigned char packetport[2];
static unsigned char packet[packet_MAXBYTES + 1];
static long long packetlen;
static unsigned char *packetnonce = packet + mc_MAGICBYTES + mc_EXTENSIONBYTES;
#endif

static struct g {
#if 0
    unsigned char message[message_MAXBYTES + 1];
#endif
    long long messagelen;
} g;

static void die(int x) {
    byte_zero(&g, sizeof g);
    _exit(x);
}

#define USAGE                                                                  \
    "usage: pok-client [-vqQ] [-t session-timeout] [-T kex-timeout] "          \
    "[-R server-pk-hash ] [ -k keydir -a authorization-hash ] host port "      \
    "[prog]"

static void usage(void) {
    log_u1(USAGE);
    die(100);
}

static void exitasap(int sig) {
    log_d3("signal ", log_num(sig), " received");
    die(111);
}

#if 0
static void exitalarm(int sig) {
    log_d3("signal ", log_num(sig), " received");
    alarm(1); /* XXX */
}
#endif

int main(int argc, char **argv) {

    char *x;
    long long i;
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
            if (*x == 'r') { serverpkhashstr = 0; continue; }
            if (*x == 'a') {
                if (x[1]) { authpkhashstr  = x + 1; break; }
                if (argv[1]) { authpkhashstr = *++argv; break; }
            }
            if (*x == 'R') {
                if (x[1]) { serverpkhashstr  = x + 1; break; }
                if (argv[1]) { serverpkhashstr = *++argv; break; }
            }
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
            usage();
        }
    }
    /* clang-format on */

    hoststr = *++argv;
    if (!hoststr) usage();
    portstr = *++argv;
    if (!portstr) usage();
    prog = *++argv;

    if (!keydir && authpkhashstr) usage();

    log_set_time(1);
    log_i1("starting");

    /* resolve host */
    log_d3("host = '", hoststr, "'");
    serveriplen = resolvehost(serverip, sizeof serverip, hoststr);
    if (serveriplen <= 0) {
        const char *why = 0;
        if (serveriplen == 0) why = ": host not found";
        log_f4("unable to resolve host '", hoststr, "'", why);
        die(111);
    }
    for (i = 0; i < serveriplen; i += 16) {
        log_d5("'", hoststr, "' resolved, IP = '", log_ip(serverip + i), "'");
    }

    /* port */
    log_d3("port = '", portstr, "'");
    if (!parseport(serverport, portstr)) {
        log_f3("unable to parse port '", portstr, "'");
        die(111);
    }

    /* authorization-hash */
    if (authpkhashstr) {
        log_d3("(option -a) authorization-hash = '", authpkhashstr, "'");
        if (!parsehex(authpkhash, sizeof authpkhash, authpkhashstr)) {
            log_f3("unable to parse -a authorization-hash string '",
                   authpkhashstr, "'");
            die(111);
        }
    }

    if (!serverpkhashstr) {
        /* resolve public-key hash from TXT record */
        if (resolvetxtkeys(serverpkhash, sizeof serverpkhash, hoststr) !=
            sizeof serverpkhash) {
            log_f2("unable to find public-key hash in the TXT record for the "
                   "host ",
                   hoststr);
            die(111);
        }
        log_d5("'", hoststr, "' TXT record resolved, pkhash = '",
               log_hex(serverpkhash, mc_HASHBYTES), "'");
    }
    else {
        /* parse public-key hash from -R option */
        log_d3("(option -R) server-pk-hash = '", serverpkhashstr, "'");
        if (!parsehex(serverpkhash, sizeof serverpkhash, serverpkhashstr)) {
            log_f3("unable to parse -R server-pk-hash string '",
                   serverpkhashstr, "'");
            die(111);
        }
    }

    /* kex-timeout */
    log_d3("(option -T) kex-timeout = '", ktimeoutstr, "'");
    if (!parsenum(&ktimeout, 1, 3600, ktimeoutstr)) {
        log_f3("unable to parse -T kex-timeout string '", ktimeoutstr, "'");
        die(111);
    }

    /* session-timeout */
    log_d3("(option -t) session-timeout = '", stimeoutstr, "'");
    if (!parsenum(&stimeout, 1, 3600, stimeoutstr)) {
        log_f3("unable to parse -t session-timeout string '", stimeoutstr, "'");
        die(111);
    }

    /* keydir */
    fdwd = open_cwd();
    if (fdwd == -1) {
        log_f1("unable to open current directory");
        die(111);
    }
    log_d3("(option -k) keydir = '", keydir, "'");
    if (keydir) {
        if (chdir(keydir) == -1) {
            log_f2("unable to change directory to ", keydir);
            die(111);
        }
    }

    /* create UDP socket */
    udpfd = socket_udp();
    if (udpfd == -1) {
        log_f1("unable to create UDP socket");
        die(111);
    }

    /* download long-term public-key */
    if (!client_downloadpk(&serverpktree, udpfd, serverip, serveriplen,
                           serverport, serverextension, serverpkhash,
                           ktimeout)) {
        log_f1("unable to download public-key");
        _exit(111);
    }
    mc_pktree_to_pk(&serverpktree, serverpk);

    /* key exchange */
    if (!client_kex(udpfd, serverip, serveriplen, serverport, serverpkhash,
                    serverpk, serverextension, authpkhash, ktimeout)) {
        log_f1("unable to exchange keys");
        _exit(111);
    }

    log_i6("finished, time = ", log_num(1000 * (seconds() - starttime)),
           " ms, packets sent = ", log_num(socket_packetssent()),
           ", received = ", log_num(socket_packetsreceived()));
    die(childstatus);
}
