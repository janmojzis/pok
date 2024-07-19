#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include "e.h"
#include "socket.h"
#include "message.h"
#include "server.h"
#include "seconds.h"
#include "byte.h"
#include "randommod.h"
#include "uint64_pack.h"
#include "uint64_unpack.h"
#include "mc.h"
#include "packet.h"

#define INCOMING 128
#define OUTGOING 128

static struct frommessage {
    unsigned char packet[OUTGOING][packet_MAXBYTES + 18];
    long long packetlen[OUTGOING];
    unsigned char message[message_MAXBYTES];
    uint64_t readid;
    uint64_t deliveredid;
} frommessage;

static struct tomessage {
    unsigned char message[INCOMING][message_MAXBYTES];
    long long messagelen[INCOMING];
    uint64_t receivedid;
    uint64_t sentid;

    /* XXX */
    unsigned char packet[packet_MAXBYTES + 1 + 18];
    unsigned char packetip[16];
    unsigned char packetport[2];
} tomessage;

static struct g {
    unsigned char nonce[mc_proto_NONCEBYTES];
    unsigned char clientip[16];
    unsigned char clientport[2];
    unsigned char extension[mc_proto_EXTENSIONBYTES];
    unsigned char clientkey[packet_KEYBYTES];
    unsigned char serverkey[packet_KEYBYTES];
    uint64_t servernonce;
    uint64_t clientnonce;
    double receivedtm;
} g;

static pid_t pid;
static int status;
static int fd = -1;
static int messagefd = -1;

static void cleanup(void) {
    unsigned char stackspace[4096];
    if (fd != -1) socket_close(fd);
    byte_zero(&g, sizeof g);
    byte_zero(&tomessage, sizeof tomessage);
    byte_zero(&frommessage, sizeof frommessage);
    byte_zero(stackspace, sizeof stackspace);
}

static void die(int x) {
    cleanup();
    _exit(x);
}

static int flagexitasap = 0;
static void signalhandler(int sig) {

    (void) sig;

    flagexitasap = 1;
}

static long long pipe_recv(int fd, unsigned char *x, long long xlen,
                           unsigned char *ip, unsigned char *port) {

    long long r = socket_recv(fd, x, xlen, 0, 0);
    if (r == -1) return -1;
    if (r > packet_MAXBYTES + 18) return -1;
    if (r < message_HEADERBYTES + mc_proto_HEADERBYTES + 18) return -1;

    byte_copy(ip, 16, x);
    byte_copy(port, 2, x + 16);
    byte_copy(x, xlen - 18, x + 18);
    r -= 18;
    return r;
}

static long long net_recv(int fd, unsigned char *x, long long xlen,
                          unsigned char *ip, unsigned char *port) {

    long long r = socket_recv(fd, x, xlen, ip, port);
    if (r == -1) return -1;
    if (r > packet_MAXBYTES) return -1;
    if (r < message_HEADERBYTES + mc_proto_HEADERBYTES) return -1;
    return r;
}

void server_child(unsigned char *ip, unsigned char *port,
                  unsigned char *nonceid, unsigned char *extension,
                  unsigned char *key, int serverfd, char **argv,
                  long long stimeout) {

    int s[2];

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, signalhandler);
    signal(SIGTERM, signalhandler);
    signal(SIGUSR1, log_inc_level);
    signal(SIGUSR2, log_dec_level);

    byte_copy(g.clientip, 16, ip);
    byte_copy(g.clientport, 2, port);
    byte_copy(g.nonce, 16, nonceid);
    byte_copy(g.extension, 32, extension);
    byte_copy(g.clientkey, packet_KEYBYTES, key);
    byte_copy(g.serverkey, packet_KEYBYTES, key + packet_KEYBYTES);
    byte_zero(key, packet_KEYBYTES + packet_KEYBYTES);
    g.servernonce = randommod(281474976710656LL);
    g.clientnonce = 0;

    /* create new UDP socket */
    fd = socket_udp();
    if (fd == -1) {
        log_f1("unable to create UDP socket");
        return;
    }

    /* create socket pair for communication with 'message handler' */
    if (socket_pair(s) == -1) {
        socket_close(fd);
        log_f1("socket_pair() failed");
        return;
    }

    /* fork new process and run 'message handler' */
    pid = fork();
    if (pid == -1) {
        log_f1("fork() failed");
        socket_close(fd);
        socket_close(s[0]);
        socket_close(s[1]);
        return;
    }
    if (pid == 0) {
        socket_close(s[0]);
        signal(SIGPIPE, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGUSR1, SIG_DFL);
        signal(SIGUSR2, SIG_DFL);
        socket_close(fd);
        message(s[1], argv, stimeout);
        die(111);
    }
    socket_close(s[1]);
    messagefd = s[0];

    while (!flagexitasap) {
        struct pollfd p[4];
        struct pollfd *q;
        struct pollfd *watchfromserver;
        struct pollfd *watchtoserver;
        struct pollfd *watchfrommessage;
        struct pollfd *watchtomessage;

        q = p;

        /* from server */
        watchfromserver = 0;
        if (tomessage.receivedid + 1 <= tomessage.sentid + INCOMING) {
            watchfromserver = q;
            q->fd = serverfd;
            q->events = POLLIN;
            ++q;
        }

        /* to server */
        watchtoserver = 0;
        if (frommessage.deliveredid + 1 <= frommessage.readid) {
            watchtoserver = q;
            q->fd = serverfd;
            q->events = POLLOUT;
            ++q;
        }

        /* from 'message handler' */
        watchfrommessage = 0;
        if (frommessage.readid + 1 <= frommessage.deliveredid + OUTGOING) {
            watchfrommessage = q;
            q->fd = messagefd;
            q->events = POLLIN;
            ++q;
        }

        /* to 'message handler' */
        watchtomessage = 0;
        if (tomessage.receivedid > tomessage.sentid) {
            watchtomessage = q;
            q->fd = messagefd;
            q->events = POLLOUT;
            ++q;
        }

        if (poll(p, q - p, -1) <= 0) {
            watchfromserver = watchfrommessage = watchtoserver =
                watchtomessage = 0;
            continue;
        }
        else {
            if (watchfromserver)
                if (!watchfromserver->revents) watchfromserver = 0;
            if (watchtoserver)
                if (!watchtoserver->revents) watchtoserver = 0;
            if (watchfrommessage)
                if (!watchfrommessage->revents) watchfrommessage = 0;
            if (watchtomessage)
                if (!watchtomessage->revents) watchtomessage = 0;
        }

        do { /* read from 'server process' */
            uint64_t id = tomessage.receivedid + 1;
            uint64_t pos = id % INCOMING;
            uint64_t packetnoncecounter;
            long long packetlen;
            unsigned char *packetextension;
            unsigned char *packetnonce;
            if (!watchfromserver) break;
            if (id > tomessage.sentid + INCOMING) break;
            packetlen =
                pipe_recv(serverfd, tomessage.packet, sizeof tomessage.packet,
                          tomessage.packetip, tomessage.packetport);
            if (packetlen < 0) {
                if (socket_temperror()) break;
                log_f1("read from 'server process' failed");
                die(111);
            }
            packetextension = tomessage.packet + mc_proto_MAGICBYTES;
            packetnonce = packetextension + mc_proto_EXTENSIONBYTES;

            packetnoncecounter = uint64_unpack(packetnonce + 16);

            if (packetnoncecounter <= g.clientnonce) {
                double tm = (seconds() - g.receivedtm) *
                            (g.clientnonce - packetnoncecounter);

                if (tm > 0.1) {
                    log_w4("received nonce <= last-nonce, nonce = ",
                           log_num(packetnoncecounter),
                           ", last-nonce = ", log_num(g.clientnonce));
                    break;
                }
            }

            packet_incoming(tomessage.packet + mc_proto_HEADERBYTES,
                            packetlen - mc_proto_HEADERBYTES);
            if (packet_decrypt(tomessage.packet + mc_proto_MAGICBYTES +
                                   mc_proto_EXTENSIONBYTES,
                               g.clientkey) != 0) {
                log_w1("unable to decrypt queryM packet");
                break;
            }
            packet_extract(tomessage.message[pos], packetlen -
                                                       mc_proto_HEADERBYTES -
                                                       mc_proto_AUTHBYTES);
            if (!packet_isok()) {
                log_w1("unable to parse queryM packet");
                break;
            }

            /* packet is verified, is safe to refresh ip/port/extension
             */
            if (!byte_isequal(g.clientip, 16, tomessage.packetip)) {
                log_d4("IP changed ", log_ip(g.clientip), " -> ",
                       log_ip(tomessage.packetip));
            }
            byte_copy(g.clientip, 16, tomessage.packetip);
            byte_copy(g.clientport, 2, tomessage.packetport);
            byte_copy(g.extension, sizeof g.extension, packetextension);

            g.clientnonce = packetnoncecounter;
            g.receivedtm = seconds();

            tomessage.messagelen[pos] =
                packetlen - mc_proto_HEADERBYTES - mc_proto_AUTHBYTES;
            ++tomessage.receivedid;

        } while (1);

        do { /* read from 'message handler' process */
            uint64_t id = frommessage.readid + 1;
            uint64_t pos = id % OUTGOING;
            unsigned char *packet;
            long long messagelen;
            if (!watchfrommessage) break;
            if (id > frommessage.deliveredid + OUTGOING) break;
            messagelen = socket_recv(messagefd, frommessage.message,
                                     sizeof frommessage.message, 0, 0);
            if (messagelen == -1)
                if (socket_temperror()) break;
            if (messagelen <= 0) {
                log_f1("read from 'message handler process' failed");
                die(111);
            }
            if (messagelen < message_HEADERBYTES) {
                log_b2("received message too short, len = ",
                       log_num(messagelen));
                die(111);
            }
            if (messagelen > message_MAXBYTES) {
                log_b2("received message too long, len = ",
                       log_num(messagelen));
                die(111);
            }

            packet = frommessage.packet[pos];

            /* nonce = id + noncecounter */
            uint64_pack(g.nonce + 16, ++g.servernonce);

            /* copy IP + PORT */
            byte_copy(packet, 16, g.clientip);
            byte_copy(packet + 16, 2, g.clientport);
            packet += 18;

            /* add encrypted content */
            packet_clear();
            packet_append(frommessage.message, messagelen);
            packet_encrypt(g.nonce, g.serverkey);
            packet_outgoing(packet + mc_proto_HEADERBYTES,
                            messagelen + mc_proto_AUTHBYTES);

            /* add magic, routing-extension, nonce */
            byte_copy(packet, mc_proto_MAGICBYTES, mc_proto_MAGICREPLYM);
            byte_copy(packet + mc_proto_MAGICBYTES, mc_proto_EXTENSIONBYTES,
                      g.extension);
            byte_copy(packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES,
                      mc_proto_NONCEBYTES, g.nonce);

            frommessage.packetlen[pos] =
                messagelen + mc_proto_HEADERBYTES + mc_proto_AUTHBYTES + 18;
            ++frommessage.readid;

        } while (1);

        do { /* send to 'server' process */
            if (!watchtoserver) break;
            if (frommessage.deliveredid + 1 > frommessage.readid) break;
            uint64_t id = frommessage.deliveredid + 1;
            uint64_t pos = id % OUTGOING;
            long long r = socket_send(serverfd, frommessage.packet[pos],
                                      frommessage.packetlen[pos], 0, 0);
            if (r == frommessage.packetlen[pos]) { ++frommessage.deliveredid; }
        } while (0);

        do { /* send to 'message handler' process */
            if (!watchtomessage) break;
            if (tomessage.sentid == tomessage.receivedid) break;
            uint64_t id = tomessage.sentid + 1;
            uint64_t pos = id % INCOMING;
            long long r = socket_send(messagefd, tomessage.message[pos],
                                      tomessage.messagelen[pos], 0, 0);
            if (r == tomessage.messagelen[pos]) { ++tomessage.sentid; }
        } while (0);
    }

    {
        long long r;
        do { r = waitpid(pid, &status, 0); } while (r == -1 && errno == EINTR);
        if (r == -1) {
            log_e1("process 'message handler' exited, but waitpid returned -1");
            die(111);
        }
    }

    if (!WIFEXITED(status)) {
        log_e2("process 'message handler' killed by signal ",
               log_num(WTERMSIG(status)));
        die(111);
    }
    if (WEXITSTATUS(status) > 0) {
        log_e2("process 'message handler' exited with status ",
               log_num(WEXITSTATUS(status)));
        die(111);
    }
    log_d1("process 'message handler' exited with status 0");
    die(0);
}
