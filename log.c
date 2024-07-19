/*
20240716

The 'log' library is used to write log messages to standard error output.
Non-printable characters are escaped.
Supports logging levels usage/bug/fatal/error/warning/info/debug/tracing.
- usage: prints information about the use of the program
- bug: prints error messages about internal problems
- fatal: prints error messages that cause the program to terminate
- error: prints error messages that cause the program to terminate from lower
  level code
- warning: prints warning messages that do not cause the program to terminate
- info: prints information that happened under normal conditions
- debug: prints information useful to debug problems
- tracing: prints much more detailed debug informations

Warning: not thread-safe.

Log format:
time: name: level: ip: message (error){file:line}[id]
time .......... optional
ip ............ optional
name .......... optional
{file:line} ... in debug/tracing level
[id] .......... optional
*/

#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "e.h"
#include "log.h"

#define STATICBUFSIZE 68 /* space for '64 characters' + '...' + '\0' */

int log_level = log_level_FATAL;
static const char *logname = 0;
static int logtime = 0;
static long long loglimit = 200;
static const char *logipstr = 0;
static char logidbuf[STATICBUFSIZE];
static const char *logid = 0;
static int logcolor = 0;

void log_set_level(int level) {
    log_level = level;
    if (level < log_level_USAGE) log_level = log_level_USAGE;
    if (level > log_level_TRACING) log_level = log_level_TRACING;
}

void log_inc_level(int signal) {
    (void) signal;
    log_set_level(log_level + 1);
}

void log_dec_level(int signal) {
    (void) signal;
    log_set_level(log_level - 1);
}

void log_set_name(const char *name) { logname = name; }
void log_set_time(int flag) { logtime = flag; }
void log_set_color(int flag) { logcolor = flag; }
void log_set_ip(const char *ip) { logipstr = ip; }
void log_set_limit(long long limit) { loglimit = limit; }
const char *log_get_id(void) { return logid; }

static char buf[256];
static unsigned long long buflen = 0;

static void flush(void) {

    char *b = buf;
    long long r;

    while (buflen > 0) {
        r = write(2, b, buflen);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) continue;
            if (errno == EWOULDBLOCK) continue;
            break;
        }
        if (r == 0) break;
        b += r;
        buflen -= r;
    }
    buflen = 0;
}

static void outch(const char x) {
    if (buflen >= sizeof buf) flush();
    buf[buflen++] = x;
}

static void outsescape(const char *x, int flaglf, long long *counter) {

    long long i;

    for (i = 0; x[i]; ++i) {
        if (counter && ++*counter > loglimit) {
            outch('.');
            outch('.');
            outch('.');
            break;
        }
        if (x[i] == '\n') {
            if (flaglf) { outch('\n'); }
            else {
                outch('\\');
                outch('n');
            }
        }
        else if (x[i] == '\r') {
            outch('\\');
            outch('r');
        }
        else if (x[i] == '\t') {
            outch('\\');
            outch('t');
        }
        else if (x[i] < 32 || x[i] > 126) {
            outch('\\');
            outch('x');
            outch("0123456789abcdef"[(x[i] >> 4) & 15]);
            outch("0123456789abcdef"[(x[i] >> 0) & 15]);
        }
        else { outch(x[i]); }
    }
}
#define outs(x) outsescape((x), 1, 0);

static char *numtostr(char *strbuf, long long strbuflen, long long n,
                      long long cnt) {

    long long len = 0;
    unsigned long long n1, n2;
    int flagsign = 0;

    if (cnt > strbuflen - 1) cnt = strbuflen - 1;

    n1 = n2 = (unsigned long long) n;
    if (n < 0) {
        n1 = -n1;
        n2 = -n2;
        flagsign = 1;
    }

    do {
        n1 /= 10;
        ++len;
    } while (n1);
    if (flagsign) ++len;
    strbuf += len;
    if (cnt > len) strbuf += cnt - len;
    *strbuf = 0;

    do {
        *--strbuf = '0' + (n2 % 10);
        n2 /= 10;
    } while (n2);
    while (cnt > len) {
        *--strbuf = '0';
        --cnt;
    }
    if (flagsign) *--strbuf = '-';

    return strbuf;
}

static void outnum(unsigned long long n, unsigned long long cnt) {

    char numbuf[STATICBUFSIZE];
    outs(numtostr(numbuf, sizeof numbuf, n, cnt));
}

void log_9_(int level, int flagerror, const char *f, unsigned long long l,
            const char *s0, const char *s1, const char *s2, const char *s3,
            const char *s4, const char *s5, const char *s6, const char *s7,
            const char *s8) {
    const char *s[9];
    long long i;
    const char *levelname;
    const char *levelcolor = 0;
    long long counter = 0;
    long long *counterptr = &counter;

    if (level > log_level) return;

    if (log_level <= 2) counterptr = 0;

    s[0] = s0;

    s[1] = s1;
    s[2] = s2;
    s[3] = s3;
    s[4] = s4;
    s[5] = s5;
    s[6] = s6;
    s[7] = s7;
    s[8] = s8;

    switch (level) {
        case 1:
            if (flagerror == 2) {
                levelname = "bug";
                levelcolor = "[95m"; /* magenta */
            }
            else {
                levelname = "fatal";
                levelcolor = "[91m"; /* bright red */
            }
            break;
        case 2:
            if (flagerror == 1) {
                levelname = "error";
                levelcolor = "[31m"; /* red */
            }
            else if (flagerror == 2) {
                levelname = "warning";
                levelcolor = "[93m"; /* yellow */
            }
            else {
                levelname = "info";
                levelcolor = "[34m"; /* blue */
            }
            break;
        case 3:
            levelname = "debug";
            break;
        case 4:
            levelname = "tracing";
            break;
        default:
            levelname = "unknown";
            break;
    }

    /* time: name: level: ip: message (error){file:line}[id] */

    /* color */
    do {
        if (!logcolor) break;
        if (!levelcolor) break;
        outch(27);
        outs(levelcolor);
    } while (0);

    /* 'time:' */
    do {
        struct tm *t;
        int saved_errno = errno;
        time_t secs = time(0);
        if (!level) break;   /* don't print in usage messages */
        if (!logtime) break; /* don't print when logtime = 0 */

        t = localtime(&secs);
        outnum(t->tm_year + 1900, 4);
        outs("-");
        outnum(t->tm_mon + 1, 2);
        outs("-");
        outnum(t->tm_mday, 2);
        outs(" ");
        outnum(t->tm_hour, 2);
        outs(":");
        outnum(t->tm_min, 2);
        outs(":");
        outnum(t->tm_sec, 2);
        outs(": ");
        errno = saved_errno;
    } while (0);

    /* 'name:' */
    do {
        if (!level) break;   /* don't print in usage messages */
        if (!logname) break; /* don't print when logname = 0 */
        outsescape(logname, 0, counterptr);
        outs(": ");
    } while (0);

    /* 'level:' */
    do {
        if (!level) break; /* don't print in usage messages */
        outs(levelname);
        outs(": ");
    } while (0);

    /* 'ip:' */
    do {
        if (!level) break;    /* don't print in usage messages */
        if (!logipstr) break; /* don't print when logipstr = 0 */
        outsescape(logipstr, 0, counterptr);
        outs(": ");
    } while (0);

    /* 'message' */
    for (i = 0; i < 9 && s[i]; ++i) outsescape(s[i], !level, counterptr);
    outs(" ");

    /* '(error)' */
    do {
        if (!level) break;     /* don't print in usage messages */
        if (!errno) break;     /* don't print when errno = 0    */
        if (!flagerror) break; /* don't print when disabled     */
        if (level >= 3) break; /* don't print in debug message  */
        outs("(");
        outs(e_str(errno));
        outs(")");
    } while (0);

    /* {file:line} */
    do {
        if (!level) break;         /* don't print in usage messages          */
        if (!f) break;             /* don't print when no f                  */
        if (!l) break;             /* don't print when no l                  */
        if (log_level <= 2) break; /* print only when debug verbosity is set */
        outs("{");
        outs(f);
        outs(":");
        outnum(l, 0);
        outs("}");
    } while (0);

    /* [id] */
    do {
        if (!level) break;         /* don't print in usage messages     */
        if (log_level <= 1) break; /* don't print in usage, fatal level */
        if (!logid) break;         /* don't print when logid = 0        */
        if (logid[0] == 0) break;  /* don't print when logid = ""       */
        outs("[");
        outsescape(logid, 0, counterptr);
        outs("]");
    } while (0);

    /* color */
    do {
        if (!logcolor) break;
        if (!levelcolor) break;
        outch(27);
        outs("[0m");
    } while (0);

    outs("\n");
    flush();
    return;
}

static char staticbuf[9][STATICBUFSIZE];
static int staticbufcounter = 0;

char *log_ip(unsigned char *ip) {
    staticbufcounter = (staticbufcounter + 1) % 9;
    if (memcmp(ip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12)) {
        struct sockaddr_in6 sa;
        memcpy(&(sa.sin6_addr), ip, 16);
        inet_ntop(AF_INET6, &(sa.sin6_addr), staticbuf[staticbufcounter],
                  STATICBUFSIZE);
    }
    else {
        struct sockaddr_in sa;
        memcpy(&(sa.sin_addr), ip + 12, 4);
        inet_ntop(AF_INET, &(sa.sin_addr), staticbuf[staticbufcounter],
                  STATICBUFSIZE);
    }
    return staticbuf[staticbufcounter];
}

char *log_port(unsigned char *port) {
    staticbufcounter = (staticbufcounter + 1) % 9;
    return numtostr(staticbuf[staticbufcounter], STATICBUFSIZE,
                    port[0] << 8 | port[1], 0);
}

char *log_num(long long num) {
    staticbufcounter = (staticbufcounter + 1) % 9;
    return numtostr(staticbuf[staticbufcounter], STATICBUFSIZE, num, 0);
}
char *log_num0(long long num, long long cnt) {
    staticbufcounter = (staticbufcounter + 1) % 9;
    return numtostr(staticbuf[staticbufcounter], STATICBUFSIZE, num, cnt);
}

static void tohex(char *x, long long xlen, const unsigned char *y,
                  long long ylen) {
    long long i;
    for (i = 0; i < ylen; ++i) {
        if (i == (xlen - 4) / 2) {
            x[2 * i + 0] = '.';
            x[2 * i + 1] = '.';
            x[2 * i + 2] = '.';
            x[2 * i + 3] = 0;
            return;
        }
        x[2 * i + 0] = "0123456789abcdef"[(y[i] >> 4) & 15];
        x[2 * i + 1] = "0123456789abcdef"[(y[i] >> 0) & 15];
    }
    x[2 * i] = 0;
}

char *log_hex(const unsigned char *y, long long ylen) {
    char *x;
    staticbufcounter = (staticbufcounter + 1) % 9;
    x = staticbuf[staticbufcounter];
    tohex(x, STATICBUFSIZE, y, ylen);
    return x;
}

void log_unset_id(void) { logid = 0; }

void log_set_id(const char *id) {

    unsigned long long i;

    for (i = 0; id[i] && i < (sizeof(logidbuf) - 4); ++i) logidbuf[i] = id[i];
    logidbuf[i] = 0;

    if (id[i]) {
        logidbuf[sizeof(logidbuf) - 4] = '.';
        logidbuf[sizeof(logidbuf) - 3] = '.';
        logidbuf[sizeof(logidbuf) - 2] = '.';
        logidbuf[sizeof(logidbuf) - 1] = 0;
    }

    logid = logidbuf;
}

void log_set_id_hex(const unsigned char *x, long long xlen) {

    tohex(logidbuf, sizeof logidbuf, x, xlen);
    logid = logidbuf;
}
