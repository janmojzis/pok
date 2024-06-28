#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <randombytes.h>
#include "open.h"
#include "writeall.h"
#include "mc.h"
#include "log.h"

#define README                                                                 \
    "\
server/public                - server public-keys\n\
server/secret                - server secret-keys\n\
server/remote                - client authorization public-keys\n\
\n\
client/<hostname>/remote     - hosts server public-keys\n\
client/<hostname>/public     - hosts authorization public-keys\n\
client/<hostname>/secret     - hosts authorization secret-keys\n\
"

static struct g {
    unsigned char sk[mc_SECRETKEYBYTESMAX];
    unsigned char pk[mc_PUBLICKEYBYTESMAX];
    unsigned char pkhash[mc_HASHBYTES];
    char pkhashhex[2 * mc_HASHBYTES + 1 + 7];
} g;

static int flagforce = 0;
static const char *keydir = 0;
static const char *alg = 0;
static struct mc mc = {0};
static const char *basedir;
static const char *clienthost = "";

static int die(int x) {
    randombytes(&g, sizeof g);
    _exit(x);
}

#define USAGE "usage: pok-makekey [-vqQf] [-m mcelieceXXXXYYY] [-a host] keydir"

static void usage(void) {
    log_u1(USAGE);
    die(100);
}

static void tohex(char *y, unsigned char *x, long long xlen) {

    long long i;

    for (i = 0; i < xlen; ++i) {
        y[2 * i + 0] = "0123456789abcdef"[15 & (x[i] >> 4)];
        y[2 * i + 1] = "0123456789abcdef"[15 & (x[i] >> 0)];
    }
    y[2 * i] = 0;
}

int mymkdir(const char *path, mode_t mode, int flagforce) {

    struct stat st;

    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            if (flagforce) { return 0; }
        }
    }
    else {
        if (errno != ENOENT) return -1;
    }
    return mkdir(path, mode);
}

int create(const char *fn, const void *x, long long xlen) {

    int fd = open_write(fn);
    if (fd == -1) return -1;
    if (writeall(fd, x, xlen) == -1) {
        close(fd);
        return -1;
    }
    return fsync(fd);
}

int main(int argc, char **argv) {

    char *x;

    log_set_name("pok-makekey");

    /* clang-format off */
    if (argc < 1) usage();
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
            if (*x == 'f') { flagforce = 1; continue; }
            if (*x == 'm') {
                if (x[1]) { alg = x + 1; break; }
                if (argv[1]) { alg = *++argv; break; }
            }
            if (*x == 'a') {
                if (x[1]) { clienthost = x + 1; break; }
                if (argv[1]) { clienthost = *++argv; break; }
            }
            usage();
        }
    }
    /* clang-format on */

    keydir = *++argv;
    if (!keydir) usage();

    if (!mc_parse(&mc, alg)) {
        log_f3("unable to parse Classic McEliece algorithm from the string '",
               alg, "'");
        die(111);
    }

    umask(022);
    if (mymkdir(keydir, 0755, flagforce) == -1) {
        log_f3("unable to make directory '", keydir, "'");
        die(111);
    }

    /* create key-directory */
    if (chdir(keydir) == -1) {
        log_f3("unable to change directory to '", keydir, "'");
        die(111);
    }

    /* add README */
    if (create("README", README, sizeof README - 1) == -1) {
        log_f3("unable to create file '", keydir, "/README'");
        die(111);
    }

    /* select client or server key */
    if (clienthost[0]) { basedir = "client/"; }
    else { basedir = "server"; }

    /* create directory server or client */
    if (mymkdir(basedir, 0755, flagforce) == -1) {
        log_f5("unable to make directory '", keydir, "/", basedir, "'");
        die(111);
    }
    if (chdir(basedir) == -1) {
        log_f5("unable to change directory to '", keydir, "/", basedir, "'");
        die(111);
    }

    /* create directory client/<hostname> */
    if (clienthost[0]) {
        if (mymkdir(clienthost, 0755, flagforce) == -1) {
            log_f6("unable to make directory '", keydir, "/", basedir,
                   clienthost, "'");
            die(111);
        }
        if (chdir(clienthost) == -1) {
            log_f6("unable to change directory '", keydir, "/", basedir,
                   clienthost, "'");
            die(111);
        }
    }

    /* generate keypair */
    mc_keypair(&mc, g.pkhash, sizeof g.pkhash, g.pk, g.sk);
    tohex(g.pkhashhex + 7, g.pkhash, sizeof g.pkhash);

    /* write public-key */
    if (mymkdir("public", 0755, flagforce) == -1) {
        log_f6("unable to make directory '", keydir, "/", basedir, clienthost,
               "/public'");
        die(111);
    }
    memcpy(g.pkhashhex, "public/", 7);
    if (create(g.pkhashhex, g.pk, mc.publickeybytes) == -1) {
        log_f8("unable to create file '", keydir, "/", basedir, clienthost, "/",
               g.pkhashhex, "'");
        die(111);
    }
    log_i9(mc.name, " public-key created '", keydir, "/", basedir, clienthost,
           "/", g.pkhashhex, "'");

    /* write secret-key */
    umask(077);
    if (mymkdir("secret", 0700, flagforce) == -1) {
        log_f6("unable to make directory '", keydir, "/", basedir, clienthost,
               "/secret'");
        die(111);
    }
    memcpy(g.pkhashhex, "secret/", 7);
    if (create(g.pkhashhex, g.sk, mc.secretkeybytes) == -1) {
        log_f8("unable to create file '", keydir, "/", basedir, clienthost, "/",
               g.pkhashhex, "'");
        die(111);
    }
    log_i9(mc.name, " secret-key created '", keydir, "/", basedir, clienthost,
           "/", g.pkhashhex, "'");

    die(0);
}
