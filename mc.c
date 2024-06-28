#include <string.h>
#include <randombytes.h>
#include "seconds.h"
#include "log.h"
#include "mc.h"

int mc_parse(struct mc *mc, const char *name) {

    int flagdefault = 0;
    long long i;

    if (!name) {
        name = mc_DEFAULTNAME;
        flagdefault = 1;
    }

    for (i = 0; mc_variants[i].name; ++i) {
        if (!strcmp(name, mc_variants[i].name)) {
            memcpy(mc, &mc_variants[i], sizeof *mc);
            break;
        }
    }

    if (!mc->name) {
        memset(mc, 0, sizeof *mc);
        log_e3("'", name, "' is not a supported Classic McEliece algorithm");
        for (i = 0; mc_variants[i].name; ++i) {
            if (!strcmp(mc_DEFAULTNAME, mc_variants[i].name)) {
                log_e3("available: '", mc_variants[i].name, "' (default)");
            }
            else { log_e3("available: '", mc_variants[i].name, "'"); }
        }
        return 0;
    }

    if (!flagdefault) {
        log_t9("'", name, "' parsed to ", mc->name,
               " Classic McEliece algorithm",
               ", publickeybytes = ", log_num(mc->publickeybytes),
               ", secretkeybytes = ", log_num(mc->secretkeybytes));
    }
    else {
        log_t7("using default ", mc->name, " Classic McEliece algorithm",
               ", publickeybytes = ", log_num(mc->publickeybytes),
               ", secretkeybytes = ", log_num(mc->secretkeybytes));
    }
    return 1;
}

int mc_fromsksize(struct mc *mc, long long sklen) {

    long long i;

    for (i = 0; mc_variants[i].name; ++i) {
        if (sklen == mc_variants[i].secretkeybytes) {
            memcpy(mc, &mc_variants[i], sizeof *mc);
            return 1;
        }
    }
    memset(mc, 0, sizeof *mc);
    return 0;
}

int mc_frompksize(struct mc *mc, long long pklen) {

    long long i;

    for (i = 0; mc_variants[i].name; ++i) {
        if (pklen == mc_variants[i].publickeybytes) {
            memcpy(mc, &mc_variants[i], sizeof *mc);
            return 1;
        }
    }
    memset(mc, 0, sizeof *mc);
    return 0;
}

int mc_fromid(struct mc *mc, unsigned char id) {

    long long i;

    id &= mc_IDMASK;

    for (i = 0; mc_variants[i].name; ++i) {
        if (id == mc_variants[i].id) {
            memcpy(mc, &mc_variants[i], sizeof *mc);
            return 1;
        }
    }
    memset(mc, 0, sizeof *mc);
    return 0;
}

/*
The mc_keypair randomly generates secret-key and corresponding public-key.
Also computes hash from public-key.
*/
void mc_keypair(struct mc *mc, unsigned char *h, long long hlen,
                unsigned char *pk, unsigned char *sk) {

    double tm;

    if (!mc->keypair) {
        log_b1("calling mc_keypair with an uninitialized mc structure");
    }

    /* keypair */
    tm = seconds();
    mc->keypair(pk, sk);
    tm = seconds() - tm;

    /* compute public-key hash */
    mceliece_xof_shake256(h, hlen, pk, mc->publickeybytes);

    log_t5(mc->name, " keypair, time = ", log_num(1000 * tm),
           " ms, pkhash = ", log_hex(h, hlen));
}

/*
The mc_enc function uses input public-key and randomly generates
a ciphertext and the corresponding session-key. The ciphertext is aligned to
mc_CIPHERTEXTBYTESMAX with random data. If the encapsulation fails,
then the output ciphertext and session-key is filled with random data.
*/
void mc_enc(struct mc *mc, unsigned char *c, unsigned char *key,
            const unsigned char *pk) {

    if (!mc->enc) {
        log_b1("calling mc_enc with an uninitialized mc structure");
    }

    unsigned char r;
    long long i;
    double tm;
    unsigned char tmpkey[mc_SESSIONKEYBYTES];
    unsigned char tmpc[mc_CIPHERTEXTBYTESMAX];

    /* random output */
    randombytes(key, mc_SESSIONKEYBYTES);
    randombytes(c, mc_CIPHERTEXTBYTESMAX);

    /* encapsulation + ciphertext alignment with random data */
    randombytes(tmpc, mc_CIPHERTEXTBYTESMAX);
    tm = seconds();
    r = mc->enc(tmpc, tmpkey, pk);
    tm = seconds() - tm;

    /* if enc() succeeds, copy session-key/ciphertext to output  */
    r = ~r;
    for (i = 0; i < mc_SESSIONKEYBYTES; ++i) tmpkey[i] ^= key[i];
    for (i = 0; i < mc_CIPHERTEXTBYTESMAX; ++i) tmpc[i] ^= c[i];
    for (i = 0; i < mc_SESSIONKEYBYTES; ++i) key[i] ^= r & tmpkey[i];
    for (i = 0; i < mc_CIPHERTEXTBYTESMAX; ++i) c[i] ^= r & tmpc[i];

    if (r == 0) { log_e2(mc->name, "enc: failed"); }
    else { log_t4(mc->name, " enc, time = ", log_num(1000 * tm), " ms"); }
}

/*
The mc_dec function uses input secret-key and input ciphertext and computes
the corresponding session-key. If the decapsulation fails,
then the output session-key is filled with random data.
*/
void mc_dec(struct mc *mc, unsigned char *key, const unsigned char *c,
            const unsigned char *sk) {

    unsigned char r;
    long long i;
    double tm;
    unsigned char tmpkey[mc_SESSIONKEYBYTES];

    if (!mc->dec) {
        log_b1("calling mc_dec with an uninitialized mc structure");
    }

    /* random output */
    randombytes(key, mc_SESSIONKEYBYTES);

    /* decapsulation */
    tm = seconds();
    r = mc->dec(tmpkey, c, sk);
    tm = seconds() - tm;

    /* if dec() succeeds, copy session-key to output  */
    r = ~r;
    for (i = 0; i < mc_SESSIONKEYBYTES; ++i) tmpkey[i] ^= key[i];
    for (i = 0; i < mc_SESSIONKEYBYTES; ++i) key[i] ^= r & tmpkey[i];

    if (r == 0) { log_e2(mc->name, "dec: failed"); }
    else { log_t4(mc->name, " dec, time = ", log_num(1000 * tm), " ms"); }
}
