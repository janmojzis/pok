/*
This file is based on mctiny_sfun.c mctiny_cfun.c.c from
https://mctiny.org/software.html
- renamed mtiny_ -> mc_mctiny_
- used parameters from struct mc instead of mctiny_XXX constants
- converted int -> long long
- reformated using clang-format
*/
#include <mceliece.h>
#include <stdint.h>
#include <string.h>
#include "crypto_stream_xsalsa20.h"
#include "log.h"
#include "mc.h"

static const unsigned char nonce[crypto_stream_xsalsa20_NONCEBYTES] = {0};

int mc_mctiny_seedisvalid(struct mc *m, const unsigned char *seed) {
    long long i, count;
    uint16_t ind[mc_mctiny_TMAX * 2];
    int32_t ind32[mc_mctiny_TMAX * 2];

    crypto_stream_xsalsa20((unsigned char *) ind, sizeof ind, nonce, seed);
    /* XXX: replicated servers must agree on endianness */

    for (i = 0; i < m->mctiny.t * 2; i++) ind[i] &= m->mctiny.mmask;

    count = 0;
    for (i = 0; i < m->mctiny.t * 2; i++)
        if (ind[i] < m->mctiny.n) ind32[count++] = ind[i];

    if (count < m->mctiny.t) return 0;

    mceliece_sort_int32(ind32, m->mctiny.t);

    for (i = 1; i < m->mctiny.t; i++)
        if (ind32[i - 1] == ind32[i]) return 0;

    return 1;
}

void mc_mctiny_seed2e(struct mc *m, unsigned char *e,
                      const unsigned char *seed) {

    unsigned char *orige = e;
    long long i, j, count;
    uint16_t ind[mc_mctiny_TMAX * 2];
    int32_t ind32[mc_mctiny_TMAX * 2];
    uint64_t e_int[1 + mc_mctiny_NMAX / 64];
    uint64_t one = 1;
    uint64_t mask;
    uint64_t val[mc_mctiny_TMAX];

    crypto_stream_xsalsa20((unsigned char *) ind, sizeof ind, nonce, seed);

    for (i = 0; i < m->mctiny.t * 2; i++) ind[i] &= m->mctiny.mmask;

    count = 0;
    for (i = 0; i < m->mctiny.t * 2; i++)
        if (ind[i] < m->mctiny.n) ind32[count++] = ind[i];

    mceliece_sort_int32(ind32, m->mctiny.t);

    for (j = 0; j < m->mctiny.t; j++) val[j] = one << (ind32[j] & 63);

    for (i = 0; i < 1 + m->mctiny.n / 64; i++) {
        e_int[i] = 0;

        for (j = 0; j < m->mctiny.t; j++) {
            mask = i ^ (ind32[j] >> 6);
            mask -= 1;
            mask >>= 63;
            mask = -mask;

            e_int[i] |= val[j] & mask;
        }
    }

    for (i = 0; i < m->mctiny.n / 64; i++) {
        *(uint64_t *) e = e_int[i];
        e += 8;
    }

    for (j = 0; j < m->mctiny.n % 64; j += 8) e[j / 8] = (e_int[i] >> j) & 0xFF;

    count = 0;
    for (i = 0; i < m->mctiny.n; ++i) count += 1 & (orige[i / 8] >> (i & 7));
    if (count != m->mctiny.t) { log_b1("count != m->mctiny.t"); }
}

void mc_mctiny_eblock2syndrome(struct mc *m, unsigned char *s,
                               const unsigned char *e,
                               const unsigned char *block, long long colpos) {
    long long i, j;
    long long epos;
    unsigned char epart[mc_mctiny_XBYTESMAX];
    unsigned char emask, tally;

    for (i = 0; i < m->mctiny.ybytes; ++i) s[i] = 0;

    if (colpos < 0) return;
    colpos *= m->mctiny.x;

    /* XXX: can do these shifts more efficiently */
    for (j = 0; j < m->mctiny.xbytes; ++j) epart[j] = 0;
    for (j = 0; j < m->mctiny.x; ++j) {
        epos = colpos + j;
        if (epos >= m->mctiny.rowbits) continue;
        epos += m->mctiny.colbits;
        emask = 1 & (e[epos / 8] >> (epos & 7));
        epart[j / 8] ^= emask << (j & 7);
    }

    for (i = 0; i < m->mctiny.y; ++i) {
        tally = 0;
        for (j = 0; j < m->mctiny.xbytes; ++j) tally ^= epart[j] & block[j];

        tally ^= tally >> 4;
        tally ^= tally >> 2;
        tally ^= tally >> 1;
        tally &= 1;
        s[i / 8] ^= tally << (i & 7);
        block += m->mctiny.xbytes;
    }
}

void mc_mctiny_pieceinit(struct mc *m, unsigned char *synd2,
                         const unsigned char *e, long long p) {
    long long i;
    long long epos;
    unsigned char bit;

    for (i = 0; i < m->mctiny.piecebytes; ++i) synd2[i] = 0;

    for (i = 0; i < m->mctiny.v * m->mctiny.y; ++i) {
        epos = p * m->mctiny.v * m->mctiny.y + i;
        if (epos < 0) continue;
        if (epos >= m->mctiny.colbits) continue;
        bit = 1 & (e[epos / 8] >> (epos & 7));
        synd2[i / 8] ^= bit << (i & 7);
    }
}

void mc_mctiny_pieceabsorb(struct mc *m, unsigned char *synd2,
                           const unsigned char *synd1, long long i) {
    long long j;
    long long outpos;
    unsigned char bit;

    if (i < 0) return;
    if (i >= m->mctiny.v) return;

    for (j = 0; j < m->mctiny.y; ++j) {
        bit = 1 & (synd1[j / 8] >> (j & 7));
        outpos = i * m->mctiny.y + j;
        synd2[outpos / 8] ^= bit << (outpos & 7);
    }
}

void mc_mctiny_finalize(struct mc *m, unsigned char *c, unsigned char *k,
                        const unsigned char *synd3, const unsigned char *e) {
    unsigned char one_ec[1 + mc_mctiny_EBYTESMAX + mc_CIPHERTEXTBYTESMAX];

    memcpy(c, synd3, m->mctiny.colbytes);

    one_ec[0] = 2;
    memcpy(one_ec + 1, e, m->mctiny.ebytes);
    mceliece_xof_shake256(c + m->mctiny.colbytes, mc_HASHBYTES, one_ec,
                          1 + m->mctiny.ebytes);

    one_ec[0] = 1;
    memcpy(one_ec + 1 + m->mctiny.ebytes, c, m->ciphertextbytes);
    mceliece_xof_shake256(k, mc_SESSIONKEYBYTES, one_ec,
                          1 + m->mctiny.ebytes + m->ciphertextbytes);
}

void mc_mctiny_pk2block(struct mc *m, unsigned char *out,
                        const unsigned char *pk, long long rowpos,
                        long long colpos) {
    long long i, j;
    unsigned char bit;

    colpos *= m->mctiny.x;
    rowpos *= m->mctiny.y;

    for (i = 0; i < m->mctiny.blockbytes; ++i) out[i] = 0;

    for (i = 0; i < m->mctiny.y; ++i) {
        if (rowpos + i < 0) continue;
        if (rowpos + i >= m->mctiny.colbits) continue;

        for (j = 0; j < m->mctiny.x; ++j) {
            if (colpos + j < 0) continue;
            if (colpos + j >= m->mctiny.rowbits) continue;

            bit = pk[m->mctiny.rowbytes * (rowpos + i) + (colpos + j) / 8];
            bit = 1 & (bit >> ((colpos + j) & 7));
            bit <<= ((i * m->mctiny.x + j) & 7);
            out[(i * m->mctiny.x + j) / 8] |= bit;
        }
    }
}

void mc_mctiny_mergepieces(
    struct mc *m, unsigned char *synd3,
    const unsigned char (*synd2)[mc_mctiny_PIECEBYTESMAX]) {
    long long i, p, j;
    unsigned char bit;

    for (i = 0; i < m->mctiny.colbytes; ++i) synd3[i] = 0;

    for (p = 0; p < m->mctiny.pieces; ++p) {
        for (i = 0; i < m->mctiny.y * m->mctiny.v; ++i) {
            j = p * m->mctiny.y * m->mctiny.v + i;
            if (j >= m->mctiny.colbits) continue;
            bit = 1 & (synd2[p][i / 8] >> (i & 7));
            synd3[j / 8] ^= bit << (j & 7);
        }
    }
}
