#include <dirent.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <randombytes.h>
#include "parsehex.h"
#include "log.h"
#include "mc.h"

static unsigned char *_map(const char *fn, long long *flen) {

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
    ret = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
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

void _mc_keys_dec(const char *text, unsigned char *k, const unsigned char *c,
                  const unsigned char *id) {

    long long i;
    char fnhex[7 + 2 * mc_HASHBYTES + 1] = "secret/";
    unsigned char *sk;
    long long sklen;
    struct mc mc;

    for (i = 0; i < mc_HASHBYTES; ++i) {
        fnhex[7 + 2 * i + 0] = "0123456789abcdef"[15 & (id[i] >> 4)];
        fnhex[7 + 2 * i + 1] = "0123456789abcdef"[15 & (id[i] >> 0)];
    }
    fnhex[7 + 2 * i] = 0;

    sk = _map(fnhex, &sklen);
    if (!sk) {
        log_w2("unable to load secret-key from ", fnhex);
        goto cleanup;
    }

    if (!mc_fromsksize(&mc, sklen)) {
        log_w4("unable to load secret-key from ", fnhex, ": bad size ",
               log_num(sklen));
        goto cleanup;
    }

    log_d5(text, " dec. using ", mc.name, " secret-key from ", fnhex);
    mc_dec(&mc, k, c, sk);
cleanup:
    if (sk) munmap(sk, sklen);
}

void mc_keys_dec(unsigned char *k, const unsigned char *c,
                 const unsigned char *id) {

    _mc_keys_dec("long-term", k, c, id);
}

static int _mc_keys_enc(const char *text, struct mc *mc, unsigned char *c,
                        unsigned char *k, const unsigned char *id) {

    char fnhex[7 + 2 * mc_HASHBYTES + 1] = "remote/";
    unsigned char *pk;
    long long i, pklen;

    randombytes(k, mc_SESSIONKEYBYTES);
    randombytes(c, mc_CIPHERTEXTBYTESMAX);

    for (i = 0; i < mc_HASHBYTES; ++i) {
        fnhex[7 + 2 * i + 0] = "0123456789abcdef"[15 & (id[i] >> 4)];
        fnhex[7 + 2 * i + 1] = "0123456789abcdef"[15 & (id[i] >> 0)];
    }
    fnhex[7 + 2 * i] = 0;

    pk = _map(fnhex, &pklen);
    if (!pk) {
        log_d3(text, " failed: unable to load public-key from ", fnhex);
        return 0;
    }

    if (!mc_frompksize(mc, pklen)) {
        log_d5(text, " failed: unable to load public-key from ", fnhex,
               ": bad size ", log_num(pklen));
        munmap(pk, pklen);
        return 0;
    }
    log_d5(text, " enc. using ", mc->name, " public-key from ", fnhex);
    mc_enc(mc, c, k, pk);
    munmap(pk, pklen);
    return 1;
}

void mc_keys_enc(unsigned char *c, unsigned char *k, const unsigned char *id) {
    struct mc mc;
    _mc_keys_enc("long-term", &mc, c, k, id);
}

const unsigned char zero[mc_HASHBYTES] = {0};

int mc_keys_authenc(unsigned char *ciphertext, unsigned char *key,
                    const unsigned char *id) {

    struct stat st;
    struct mc mc;

    if (stat("remote/", &st) == -1) {
        if (errno == ENOENT) {
            memset(key, 0, mc_SESSIONKEYBYTES);
            randombytes(ciphertext, mc_CIPHERTEXTBYTESMAX);
            if (memcmp(zero, id, sizeof zero)) {
                log_e1("authorization requested by client but not desired by "
                       "server: directory remote/ doesn't exist");
            }
            else {
                log_d1("authorization not requested by client and not desired "
                       "by server: directory remote/ doesn't exist");
            }
            errno = 0;
            return 1;
        }
        randombytes(key, mc_SESSIONKEYBYTES);
        randombytes(ciphertext, mc_CIPHERTEXTBYTESMAX);
        log_w1("authorization failed: unable to stat(2) directory remote/");
        return 0;
    }
    if (!memcmp(zero, id, sizeof zero)) {
        errno = 0;
        log_e1("authorization not requested by client but desired by server");
        return 0;
    }
    log_d1("authorization requested by client and desired by server");
    return _mc_keys_enc("authorization", &mc, ciphertext, key, id);
}

void mc_keys_authdec(unsigned char *k, const unsigned char *c,
                     const unsigned char *id) {

    struct stat st;

    if (stat("secret/", &st) == -1) {
        if (errno == ENOENT) {
            memset(k, 0, mc_SESSIONKEYBYTES);
            /* log_w1("no secret/ directory - authorization not desired"); */
            errno = 0;
            return;
        }
        randombytes(k, mc_SESSIONKEYBYTES);
        log_w1("unable to stat(2) directory secret/");
        return;
    }
    _mc_keys_dec("authorization", k, c, id);
}

int mc_keys(unsigned char *out, long long outlen, const char *d) {

    DIR *dir;
    struct dirent *dirent;
    long long i, len = 0;

    for (i = 0; i < outlen; ++i) out[i] = 0;

    dir = opendir(d);
    if (!dir) {
        /* log_w3("unable to open directory '", d, "'"); */
        return 0;
    }

    for (;;) {
        errno = 0;
        dirent = readdir(dir);
        if (!dirent) {
            if (errno) {
                log_w3("unable to read directory '", d, "'");
                closedir(dir);
                return 0;
            }
            break;
        }
        if (dirent->d_name[0] == '.') continue;
        if (len + mc_HASHBYTES <= outlen) {
            if (!parsehex(out, mc_HASHBYTES, dirent->d_name)) {
                log_w4("unable to parse public-key id from ", d, "/",
                       dirent->d_name);
                continue;
            }
            len += mc_HASHBYTES;
            out += mc_HASHBYTES;
        }
    }
    closedir(dir);

    if (!len) {
        log_w3("no public-keys in directory '", d, "'");
        return 0;
    }

    return 1;
}
