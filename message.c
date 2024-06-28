#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include "byte.h"
#include "uint8_pack.h"
#include "uint8_unpack.h"
#include "uint16_pack.h"
#include "uint16_unpack.h"
#include "uint32_pack.h"
#include "uint32_unpack.h"
#include "uint64_pack.h"
#include "uint64_unpack.h"
#include "log.h"
#include "pacing.h"
#include "dupforkexec.h"
#include "seconds.h"
#include "randommod.h"
#include "blocking.h"
#include "socket.h"
#include "message.h"

#define SCHEDULING_TOLERANCE 0.001

static long long sessiontimeout;
static double sessiondeadline;

#define OUTGOING 128
#define INCOMING (2 * OUTGOING)

static struct fromchild {
    int fd;
    int sendeof;
    int sendeofacked;
    int failuredelivered;
    struct pacing_connection pacingc;
    unsigned char block[OUTGOING][message_MAXBYTES];
    uint16_t blocklen[OUTGOING];
    int blockacked[OUTGOING];
    uint64_t readid;
    uint64_t deliveredid;
    struct pacing_packet blockpacing[OUTGOING];
} fromchild;

static struct tochild {
    int fd;
    int eofdelivered;
    int sendfailure;
    unsigned char block[INCOMING][message_MAXBYTES];
    uint16_t blocklen[INCOMING];
    uint16_t blockpos[INCOMING];
    int blockreceived[INCOMING];
    int blockacknowledged[INCOMING];
    uint64_t receivedid;
    uint64_t writtenid;
    unsigned char buf[message_MAXBYTES + 1];
} tochild;

static void tochild_close(void) {
    if (tochild.fd != -1) {
        close(tochild.fd);
        tochild.fd = -1;
    }
}

static void tochild_dropbuffers(void) {
    uint64_t id;
    if (tochild.writtenid != tochild.receivedid) {
        log_w4("dropping buffers: writtenid = ", log_num(tochild.writtenid),
               ", receivedid = ", log_num(tochild.receivedid));
        for (id = tochild.writtenid + 1; id <= tochild.receivedid; ++id) {
            uint64_t pos = id % INCOMING;
            tochild.blockreceived[pos] = 0;
            tochild.blockacknowledged[pos] = 0;
            tochild.blockpos[pos] = 0;
        }
        tochild.writtenid = tochild.receivedid;
    }
}

static void cleanup(void) {
    tochild_close();
    byte_zero(&tochild, sizeof tochild);
    byte_zero(&fromchild, sizeof fromchild);
}

static void die(int x) {
    cleanup();
    _exit(x);
}

static void acknowledged(uint64_t start, uint64_t stop) {

    uint64_t id, pos;
    if (start == stop) return;
    if (start > stop) {
        log_b4("start > stop, start = ", log_num(start),
               ", stop = ", log_num(stop));
        return;
    }
    if (start > fromchild.readid) {
        log_b1("start > fromchild.readid");
        return;
    }
    if (stop > fromchild.readid) {
        log_b1("stop > fromchild.readid");
        return;
    }
    if (fromchild.deliveredid > start) start = fromchild.deliveredid;
    if (stop > fromchild.readid) stop = fromchild.readid;
    if (start >= stop) return;

    for (id = start + 1; id <= stop; ++id) {
        pos = id % OUTGOING;
        if (!fromchild.blockacked[pos]) {
            fromchild.blockacked[pos] = 1;
            pacing_acknowledged(&fromchild.pacingc,
                                &fromchild.blockpacing[pos]);
            message_log("acknowledged", fromchild.block[pos]);
        }
    }
}

static int flagsendack = 0;
static double pingdeadline = 0.0;
static int flagexitasap = 0;

static void failure_put(unsigned char *buf) {
    if (tochild.sendfailure) {
        uint16_t messagelen = uint16_unpack(buf + 30);
        messagelen |= tochild.sendfailure;
        uint16_pack(buf + 30, messagelen);
    }
}

#define U32MAX 4294967295
#define U16MAX 65535
#define U8MAX 255

static void ack_put(unsigned char *buf) {

    uint64_t pos, stop, start;
    uint64_t begin = tochild.writtenid;
    uint64_t end = tochild.receivedid;

    /* range1  */
    start = begin;
    for (stop = start; stop < end; ++stop) {
        pos = (stop + 1) % INCOMING;
        if (!tochild.blockreceived[pos]) break;
        tochild.blockacknowledged[pos] += 1;
    }
    uint64_pack(buf, stop);

    /* range2 */
    for (start = stop; start < end && start < stop + U32MAX; ++start) {
        pos = (start + 1) % INCOMING;
        if (tochild.blockreceived[pos] && tochild.blockacknowledged[pos] < 1)
            break;
    }
    uint32_pack(buf + 8, start - stop);
    for (stop = start; stop < end && stop < start + U16MAX; ++stop) {
        pos = (stop + 1) % INCOMING;
        if (!tochild.blockreceived[pos]) break;
        tochild.blockacknowledged[pos] += 1;
    }
    uint16_pack(buf + 12, stop - start);

    /* range3 */
    for (start = stop; start < end && start < stop + U8MAX; ++start) {
        pos = (start + 1) % INCOMING;
        if (tochild.blockreceived[pos] && tochild.blockacknowledged[pos] < 1)
            break;
    }
    uint8_pack(buf + 14, start - stop);
    for (stop = start; stop < end && stop < start + U8MAX; ++stop) {
        pos = (stop + 1) % INCOMING;
        if (!tochild.blockreceived[pos]) break;
        tochild.blockacknowledged[pos] += 1;
    }
    uint8_pack(buf + 15, stop - start);

    /* range4 */
    for (start = stop; start < end && start < stop + U8MAX; ++start) {
        pos = (start + 1) % INCOMING;
        if (tochild.blockreceived[pos] && tochild.blockacknowledged[pos] < 1)
            break;
    }
    uint8_pack(buf + 16, start - stop);
    for (stop = start; stop < end && stop < start + U8MAX; ++stop) {
        pos = (stop + 1) % INCOMING;
        if (!tochild.blockreceived[pos]) break;
        tochild.blockacknowledged[pos] += 1;
    }
    uint8_pack(buf + 17, stop - start);

    /* range5 */
    for (start = stop; start < end && start < stop + U8MAX; ++start) {
        pos = (start + 1) % INCOMING;
        if (tochild.blockreceived[pos] && tochild.blockacknowledged[pos] < 1)
            break;
    }
    uint8_pack(buf + 18, start - stop);
    for (stop = start; stop < end && stop < start + U8MAX; ++stop) {
        pos = (stop + 1) % INCOMING;
        if (!tochild.blockreceived[pos]) break;
        tochild.blockacknowledged[pos] += 1;
    }
    uint8_pack(buf + 19, stop - start);

    /* range6 */
    for (start = stop; start < end && start < stop + U8MAX; ++start) {
        pos = (start + 1) % INCOMING;
        if (tochild.blockreceived[pos] && tochild.blockacknowledged[pos] < 1)
            break;
    }
    uint8_pack(buf + 20, start - stop);
    for (stop = start; stop < end && stop < start + U8MAX; ++stop) {
        pos = (stop + 1) % INCOMING;
        if (!tochild.blockreceived[pos]) break;
        tochild.blockacknowledged[pos] += 1;
    }
    uint8_pack(buf + 21, stop - start);
}

#undef U32MAX
#undef U16MAX
#undef U8MAX

static void message_enqueue(int s, unsigned char *buf, long long len) {

    /* insert failure flag */
    failure_put(buf);

    /* insert acknowledgements */
    ack_put(buf);

    if (socket_enqueue(s, buf, len, 0, 0) == -1) {
        if (socket_temperror()) return;
        log_f1("send to server failed");
        die(111);
    }

    message_log("transmitted", (unsigned char *) buf);

    /* refresh ping timeout */
    pingdeadline =
        seconds() + ((double) sessiontimeout / 10.0) + ((double) randommod(2));

    /* reset flagsendack */
    flagsendack = 0;
}

static double trytransmitting(int s, double when) {

    double when2;
    uint64_t pos, id;

    for (id = fromchild.deliveredid + 1; id <= fromchild.readid; ++id) {
        pos = id % OUTGOING;

        if (fromchild.blockacked[pos]) continue;

        when2 = pacing_whenrto(&fromchild.pacingc, &fromchild.blockpacing[pos]);
        if (when2 <= SCHEDULING_TOLERANCE) {
            message_enqueue(s, fromchild.block[pos], message_MAXBYTES);
            pacing_transmitted(&fromchild.pacingc, &fromchild.blockpacing[pos]);
            return 0;
        }
        if (when2 < when) when = when2;
    }
    return when;
}

void message(int s, char **argv, long long stimeout) {

    pid_t child = -1;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGUSR1, log_inc_level);
    signal(SIGUSR2, log_dec_level);

    if (*argv) {
        log_i3("starting message handler and executing program '", argv[0],
               "'");
        child = dupforkexec(&fromchild.fd, &tochild.fd, argv);
        if (child == -1) {
            log_f1("unable to dupforkexec()");
            die(111);
        }
    }
    else {
        log_i1("starting message handler and input/output redirected to "
               "stdin/stdout");
        blocking_disable(0);
        fromchild.fd = 0;
        blocking_disable(1);
        tochild.fd = 1;
    }

    pacing_connection_init(&fromchild.pacingc);

    sessiontimeout = stimeout;
    sessiondeadline = seconds() + sessiontimeout;

    while (!flagexitasap) {
        long long r;
        double when, when2;
        struct pollfd p[4];
        struct pollfd *q;
        struct pollfd *watchfromserver;
        struct pollfd *watchfromchild;
        struct pollfd *watchtochild;

        /* finish */
        if (log_level >= log_level_TRACING) {
            if (fromchild.sendeof || fromchild.sendeofacked ||
                tochild.eofdelivered || tochild.fd == -1) {
                log_t8(
                    "finish check: fromchild.sendeofacked = ",
                    log_num(fromchild.sendeofacked),
                    ",  tochild.writtenid == tochild.receivedid = ",
                    log_num(tochild.writtenid == tochild.receivedid),
                    ", tochild.eofdelivered = ", log_num(tochild.eofdelivered),
                    ", tochild.fd = ", log_num(tochild.fd));
            }
        }
        if (fromchild.sendeofacked > 0 || fromchild.failuredelivered) {
            if (tochild.writtenid == tochild.receivedid) {
                if (tochild.eofdelivered > 0) {
                    if (tochild.fd == -1) {
                        flagsendack = 1;
                        flagexitasap = 1;
                    }
                }
            }
        }

        pacing_now_update(&fromchild.pacingc);

        /* timeout */
        when2 = sessiondeadline - seconds();
        if (when2 < 0.0) {
            errno = ETIMEDOUT;
            log_f1("message failed");
            die(111);
        }

        /* try send packets */
        for (long long i = 0; i < 10; ++i) {
            when = pacing_whendecongested(&fromchild.pacingc, message_MAXBYTES);
            if (when > SCHEDULING_TOLERANCE) break;
            when = trytransmitting(s, when2);
            if (when > SCHEDULING_TOLERANCE) break;
        }

        /* try send ping / pure acknowledgement */
        when2 = pingdeadline - seconds();
        if (when2 <= 0) {
            flagsendack = 1;
            log_t1("ping");
        }

        if (!flagsendack)
            if (tochild.writtenid < tochild.receivedid)
                if (!tochild.blockacknowledged[tochild.receivedid % INCOMING])
                    flagsendack = 1;

        if (flagsendack) {
            unsigned char buf[message_HEADERBYTES] = {0};
            message_enqueue(s, buf, message_HEADERBYTES);
        }

        q = p;

        /* from child */
        watchfromchild = q;
        if (fromchild.sendeof) watchfromchild = 0;
        if ((fromchild.readid + 1) > fromchild.deliveredid + OUTGOING)
            watchfromchild = 0; /* must be space at least for one block */
        if (watchfromchild) {
            q->fd = fromchild.fd;
            q->events = POLLIN;
            ++q;
        }

        /* from server */
        watchfromserver = q;
        q->fd = s;
        q->events = POLLIN;
        ++q;

        /* to child */
        watchtochild = q;
        if (tochild.writtenid == tochild.receivedid) watchtochild = 0;
        if (tochild.writtenid < tochild.receivedid) {
            uint64_t id = tochild.writtenid + 1;
            uint64_t pos = id % INCOMING;
            if (!tochild.blockreceived[pos]) watchtochild = 0;
        }
        if (watchtochild) {
            q->fd = tochild.fd;
            q->events = POLLOUT;
            ++q;
        }

        if (when < 0.0) when = 0.0;
        if (socket_poll_and_dequeue(p, q - p, 1000 * when) < 0) {
            watchfromserver = watchfromchild = watchtochild = 0;
            log_w1("poll failed");
        }
        else {
            if (watchfromchild)
                if (!watchfromchild->revents) watchfromchild = 0;
            if (watchfromserver)
                if (!watchfromserver->revents) watchfromserver = 0;
            if (watchtochild)
                if (!watchtochild->revents) watchtochild = 0;
        }
        pacing_now_update(&fromchild.pacingc);

        do { /* read from child */
            uint64_t id = fromchild.readid + 1;
            uint64_t pos = id % OUTGOING;
            if (!watchfromchild) break;
            if (id > fromchild.deliveredid + OUTGOING) break;
            if (fromchild.sendeof) break;
            r = read(fromchild.fd, fromchild.block[pos] + message_HEADERBYTES,
                     message_BLOCKBYTES);
            if (r == -1)
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                    break;
            if (r <= 0) {
                log_t1("child eof");
                if (r < 0) log_w1("child eof - read failed");
                r = fromchild.sendeof = message_EOF;
            }
            if (fromchild.sendeof) {
                sessiontimeout = stimeout / 10;
                if (sessiondeadline > seconds() + sessiontimeout) {
                    sessiondeadline = seconds() + sessiontimeout;
                }
            }
            fromchild.blocklen[pos] = r;
            fromchild.blockacked[pos] = 0;
            pacing_packet_init(&fromchild.blockpacing[pos], message_MAXBYTES);
            byte_zero(fromchild.block[pos], message_HEADERBYTES);
            uint64_pack(fromchild.block[pos] + 22, id);
            uint16_pack(fromchild.block[pos] + 30, fromchild.blocklen[pos]);
            if (message_BLOCKBYTES > r) {
                byte_zero(fromchild.block[pos] + message_HEADERBYTES + r,
                          message_BLOCKBYTES - r);
            }
            message_log("readed", fromchild.block[pos]);
            ++fromchild.readid;
        } while (0);

        do { /* read from server */
            uint64_t messageid, stop, start;
            uint16_t messagelen, messageeof, messagefail;
            if (!watchfromserver) break;
            r = socket_recv(s, tochild.buf, sizeof tochild.buf, 0, 0);
            if (r == -1)
                if (socket_temperror()) break;
            if (r <= 0) {
                log_f1("read from server failed");
                die(111);
            }
            if (r < message_HEADERBYTES) {
                log_b2("received message too short, len = ", log_num(r));
                die(111);
            }
            if (r > message_MAXBYTES) {
                log_b2("received message too long, len = ", log_num(r));
                die(111);
            }
            sessiondeadline = seconds() + sessiontimeout;

            /* process message */
            messageid = uint64_unpack(tochild.buf + 22);
            messagelen = uint16_unpack(tochild.buf + 30);
            messagefail = messagelen & message_FAILURE;
            messageeof = messagelen & message_EOF;
            messagelen = messagelen & message_LENMASK;

            if (r < messagelen + message_HEADERBYTES) {
                log_b4("received message too short, len = ", log_num(r),
                       ", messagelen = ", log_num(messagelen));
                break;
            }

            if (!fromchild.failuredelivered && messagefail) {
                errno = 0;
                log_w1("remote child failed");
                fromchild.failuredelivered = messagefail;
            }

            if ((messagelen | messageeof) > 0) {
                if (tochild.writtenid + INCOMING >= messageid) {
                    if (messageid > tochild.writtenid) {
                        uint64_t pos = messageid % INCOMING;
                        if (!tochild.blockreceived[pos]) {
                            byte_copy(tochild.block[pos],
                                      message_HEADERBYTES + messagelen,
                                      tochild.buf);
                            tochild.blocklen[pos] = messagelen | messageeof;
                            tochild.blockreceived[pos] = 1;
                            if (messageid > tochild.receivedid) {
                                tochild.receivedid = messageid;
                            }
                        }
                        tochild.blockacknowledged[pos] = 0;
                        message_log("received", tochild.buf);
                    }
                    else { message_log("old", tochild.buf); }
                    flagsendack = 1;
                }
                else { message_log("dropped", tochild.buf); }
            }
            else { message_log("received", tochild.buf); }

            /* process acknowledgements */
            stop = uint64_unpack(tochild.buf);
            acknowledged(0, stop);
            start = stop + uint32_unpack(tochild.buf + 8);
            stop = start + uint16_unpack(tochild.buf + 12);
            acknowledged(start, stop);
            start = stop + uint8_unpack(tochild.buf + 14);
            stop = start + uint8_unpack(tochild.buf + 15);
            acknowledged(start, stop);
            start = stop + uint8_unpack(tochild.buf + 16);
            stop = start + uint8_unpack(tochild.buf + 17);
            acknowledged(start, stop);
            start = stop + uint8_unpack(tochild.buf + 18);
            stop = start + uint8_unpack(tochild.buf + 19);
            acknowledged(start, stop);
            start = stop + uint8_unpack(tochild.buf + 20);
            stop = start + uint8_unpack(tochild.buf + 21);
            acknowledged(start, stop);

        } while (1);

        /* delivered blocks */
        while (fromchild.deliveredid + 1 <= fromchild.readid) {
            uint64_t id = fromchild.deliveredid + 1;
            uint64_t pos = id % OUTGOING;
            if (!fromchild.blockacked[pos]) break;
            if (fromchild.blocklen[pos] & message_EOF) {
                fromchild.sendeofacked = 1;
            }
            message_log("delivered", fromchild.block[pos]);
            ++fromchild.deliveredid;
        }

        /* write to child */
        while (tochild.writtenid + 1 <= tochild.receivedid) {

            if (!watchtochild) break;

            uint64_t id = tochild.writtenid + 1;
            uint64_t pos = id % INCOMING;
            uint16_t messagelen, messageeof, messagepos;
            unsigned char *messagebuf;

            if (!tochild.blockreceived[pos]) break;

            messagelen = tochild.blocklen[pos] & message_LENMASK;
            messageeof = tochild.blocklen[pos] & message_EOF;
            messagepos = tochild.blockpos[pos];
            messagebuf = tochild.block[pos];

            if (messagelen - messagepos > 0) {
                r = write(tochild.fd,
                          messagebuf + message_HEADERBYTES + messagepos,
                          messagelen - messagepos);
                if (r == -1)
                    if (errno == EINTR || errno == EAGAIN ||
                        errno == EWOULDBLOCK)
                        break;
                if (r <= 0) {
                    log_w1("write to child failed");
                    tochild.sendfailure = message_FAILURE;
                    tochild_dropbuffers();
                    tochild_close();
                    break;
                }

                if (r + messagepos < messagelen) {
                    /* partial write */
                    tochild.blockpos[pos] = r + messagepos;
                    break;
                }
                message_log("written", messagebuf);
            }
            if (messageeof) {
                tochild.eofdelivered = messageeof;
                tochild_close();
                message_log("written", messagebuf);
            }
            tochild.blockreceived[pos] = 0;
            tochild.blockacknowledged[pos] = 0;
            tochild.blockpos[pos] = 0;
            ++tochild.writtenid;
        }
    }

    {
        long long snd = pacing_connection_packetssent(&fromchild.pacingc);
        long long rcv = pacing_connection_packetsreceived(&fromchild.pacingc);
        long long rt = snd - rcv;
        long long loss = -100 + (100 * snd) / rcv;

        log_d9("messages sent = ", log_num(snd),
               ", acknowledged = ", log_num(rcv),
               ", retransmitted = ", log_num(rt),
               ", packet loss = ", log_num(loss), "%");
    }
    {
        int exitcode = 0;
        unsigned char buf[message_HEADERBYTES];
        byte_zero(buf, message_HEADERBYTES);
        failure_put(buf);
        ack_put(buf);

        if (*argv) { exitcode = dupforkexec_wait(child, argv); }
        log_i1("message handler finished");

        /* XXX */
        usleep(150);
        socket_send(s, buf, sizeof buf, 0, 0);
        usleep(270);
        socket_send(s, buf, sizeof buf, 0, 0);
        usleep(580);
        socket_send(s, buf, sizeof buf, 0, 0);

        die(exitcode);
    }
}
