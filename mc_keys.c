#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "mc.h"
#include "byte.h"
#include "log.h"
#include "mc.h"

static unsigned char *map_(const char *fn, long long *flen) {

    int fd = -1;
    unsigned char *ret = MAP_FAILED;
    struct stat st;

    fd = open(fn, O_RDONLY | O_NONBLOCK);
    if (fd == -1) {
        log_w2("unable to open(2) ", fn);
        goto cleanup;
    }
    if (fstat(fd, &st) == -1) {
        log_w2("unable to stat(2) ", fn);
        goto cleanup;
    }
    ret = mmap(0, (size_t) st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (ret == MAP_FAILED) {
        log_w2("unable to mmap(2) ", fn);
        goto cleanup;
    }
    *flen = st.st_size;

cleanup:
    if (fd != -1) close(fd);
    if (ret == MAP_FAILED) ret = 0;
    return ret;
}

void mc_keys_dec(unsigned char *k, const unsigned char *c,
                 const unsigned char *id) {

    long long i;
    char fnhex[7 + 2 * mc_HASHBYTES + 1] = "secret/";
    unsigned char *sk;
    long long sklen;

    for (i = 0; i < mc_HASHBYTES; ++i) {
        fnhex[7 + 2 * i + 0] = "0123456789abcdef"[15 & (id[i] >> 4)];
        fnhex[7 + 2 * i + 1] = "0123456789abcdef"[15 & (id[i] >> 0)];
    }
    fnhex[7 + 2 * i] = 0;

    sk = map_(fnhex, &sklen);
    if (!sk) {
        log_w2("unable to load secret-key from ", fnhex);
        goto cleanup;
    }

    if (sklen != mc_SECRETKEYBYTES) {
        log_w4("unable to load secret-key from ", fnhex, ": bad size ",
               log_num(sklen));
        goto cleanup;
    }

    log_t3(mc_NAME, " dec, secret-key from ", fnhex);
    mc_dec(k, c, sk);
cleanup:
    if (sk) munmap(sk, sklen);
}

int mc_keys_loadpk(unsigned char *out, const unsigned char *id) {

    long long i, pklen;
    char fnhex[7 + 2 * mc_HASHBYTES + 1] = "public/";
    unsigned char *pk;
    int ret = 0;

    for (i = 0; i < mc_HASHBYTES; ++i) {
        fnhex[7 + 2 * i + 0] = "0123456789abcdef"[15 & (id[i] >> 4)];
        fnhex[7 + 2 * i + 1] = "0123456789abcdef"[15 & (id[i] >> 0)];
    }
    fnhex[7 + 2 * i] = 0;

    pk = map_(fnhex, &pklen);
    if (!pk) {
        log_w2("unable to load public-key from ", fnhex);
        goto cleanup;
    }
    if (pklen != mc_PUBLICKEYBYTES) {
        log_w4("unable to load public-key from ", fnhex, ": bad size ",
               log_num(pklen));
        goto cleanup;
    }

    byte_copy(out, pklen, pk);
    log_t5(fnhex, " public key ", mc_NAME, " loaded from ", fnhex);
    ret = 1;
cleanup:
    if (pk && pklen > 0) munmap(pk, (unsigned long long) pklen);
    return ret;
}
