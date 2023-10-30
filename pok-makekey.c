#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "writeall.h"
#include "open.h"
#include "byte.h"
#include "log.h"
#include "e.h"
#include "mc.h"

static struct g {
    unsigned char sk[mc_SECRETKEYBYTES];
    unsigned char pk[mc_PUBLICKEYBYTES];
    struct mc_pktree pktree;
    char hexhash[2 * mc_HASHBYTES + 1 + 7];
} g;

static int flagforce = 0;
static const char *keydir = 0;

static int die(int x) {
    byte_zero(&g, sizeof g);
    _exit(x);
}

#define USAGE "usage: pok-makekey [-vqQf] keydir"

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

static int mymkdir(const char *path, mode_t mode, int force) {

    struct stat st;

    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            if (force) { return 0; }
        }
    }
    else {
        if (errno != ENOENT) return -1;
    }
    return mkdir(path, mode);
}

static int create(const char *fn, const void *x, long long xlen) {

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
    log_set_level(log_level_ERROR);

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
            if (*x == 'q') { log_set_level(log_level_FATAL); continue; }
            if (*x == 'Q') { log_set_level(log_level_ERROR); continue; }
            if (*x == 'v') { log_inc_level(/*dummy*/0); continue; }
            if (*x == 'f') { flagforce = 1; continue; }
            usage();
        }
    }
    /* clang-format on */

    keydir = *++argv;
    if (!keydir) usage();

    /* create key-directory */
    umask(022);
    if (mymkdir(keydir, 0755, flagforce) == -1) {
        log_f3("unable to create directory '", keydir, "'");
        die(111);
    }

    if (chdir(keydir) == -1) {
        log_f3("unable to change directory to '", keydir, "'");
        die(111);
    }

    /* generate keypair */
    mc_keypair(g.pk, g.sk);
    mc_pktree_pk2tree(&g.pktree, g.pk);
    tohex(g.hexhash + 7, g.pktree.l0, sizeof g.pktree.l0);

    /* write public-key */
    if (mymkdir("public", 0755, flagforce) == -1) {
        log_f3("unable to make directory '", keydir, "/public'");
        die(111);
    }
    byte_copy(g.hexhash, 7, "public/");
    if (create(g.hexhash, g.pk, sizeof g.pk) == -1) {
        log_f5("unable to create file '", keydir, "/", g.hexhash, "'");
        die(111);
    }
    log_i6(mc_NAME, " public-key created '", keydir, "/", g.hexhash, "'");

    /* write secret-key */
    umask(077);
    if (mymkdir("secret", 0700, flagforce) == -1) {
        log_f3("unable to make directory '", keydir, "/secret'");
        die(111);
    }
    byte_copy(g.hexhash, 7, "secret/");
    if (create(g.hexhash, g.sk, sizeof g.sk) == -1) {
        log_f5("unable to create file '", keydir, "/", g.hexhash, "'");
        die(111);
    }
    log_i6(mc_NAME, " secret-key created '", keydir, "/", g.hexhash, "'");

    die(0);
}
