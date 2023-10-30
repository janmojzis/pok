/*
This file is based on mctiny_sfun.c mctiny_cfun.c.c from
https://mctiny.org/software.html
- rename mtiny_ -> mc_mctiny_
- convert int -> long long
- reformat using clang-format
*/

#include "mc.h"
#include "log.h"
#include <mceliece.h>
#include <stdint.h>
#include <string.h>
#include "crypto_stream_xsalsa20.h"

static const unsigned char nonce[crypto_stream_xsalsa20_NONCEBYTES];

int mc_mctiny_seedisvalid(const unsigned char *seed) {
    long long i, count;
    uint16_t ind[mc_mctiny_T * 2];
    int32_t ind32[mc_mctiny_T * 2];

    crypto_stream_xsalsa20((unsigned char *) ind, sizeof ind, nonce, seed);
    /* XXX: replicated servers must agree on endianness */

    for (i = 0; i < mc_mctiny_T * 2; i++) ind[i] &= mc_mctiny_MMASK;

    count = 0;
    for (i = 0; i < mc_mctiny_T * 2; i++)
        if (ind[i] < mc_mctiny_N) ind32[count++] = ind[i];

    if (count < mc_mctiny_T) return 0;

    mceliece_sort_int32(ind32, mc_mctiny_T);

    for (i = 1; i < mc_mctiny_T; i++)
        if (ind32[i - 1] == ind32[i]) return 0;

    return 1;
}

void mc_mctiny_seed2e(unsigned char *e, const unsigned char *seed) {
    unsigned char *orige = e;
    long long i, j, count;
    uint16_t ind[mc_mctiny_T * 2];
    int32_t ind32[mc_mctiny_T * 2];
    uint64_t e_int[1 + mc_mctiny_N / 64];
    uint64_t one = 1;
    uint64_t mask;
    uint64_t val[mc_mctiny_T];

    crypto_stream_xsalsa20((unsigned char *) ind, sizeof ind, nonce, seed);

    for (i = 0; i < mc_mctiny_T * 2; i++) ind[i] &= mc_mctiny_MMASK;

    count = 0;
    for (i = 0; i < mc_mctiny_T * 2; i++)
        if (ind[i] < mc_mctiny_N) ind32[count++] = ind[i];

    mceliece_sort_int32(ind32, mc_mctiny_T);

    for (j = 0; j < mc_mctiny_T; j++) val[j] = one << (ind32[j] & 63);

    for (i = 0; i < 1 + mc_mctiny_N / 64; i++) {
        e_int[i] = 0;

        for (j = 0; j < mc_mctiny_T; j++) {
            mask = i ^ (ind32[j] >> 6);
            mask -= 1;
            mask >>= 63;
            mask = -mask;

            e_int[i] |= val[j] & mask;
        }
    }

    for (i = 0; i < mc_mctiny_N / 64; i++) {
        *(uint64_t *) e = e_int[i];
        e += 8;
    }

    for (j = 0; j < mc_mctiny_N % 64; j += 8) e[j / 8] = (e_int[i] >> j) & 0xFF;

    count = 0;
    for (i = 0; i < mc_mctiny_N; ++i) count += 1 & (orige[i / 8] >> (i & 7));
    if (count != mc_mctiny_T) { log_b1("count != mc_mctiny_T"); }
}

void mc_mctiny_eblock2syndrome(unsigned char *s, const unsigned char *e,
                               const unsigned char *block, long long colpos) {
    long long i, j;
    long long epos;
    unsigned char epart[mc_mctiny_XBYTES];
    unsigned char emask, tally;

    for (i = 0; i < mc_mctiny_YBYTES; ++i) s[i] = 0;

    if (colpos < 0) return;
    colpos *= mc_mctiny_X;

    /* XXX: can do these shifts more efficiently */
    for (j = 0; j < mc_mctiny_XBYTES; ++j) epart[j] = 0;
    for (j = 0; j < mc_mctiny_X; ++j) {
        epos = colpos + j;
        if (epos >= mc_mctiny_ROWBITS) continue;
        epos += mc_mctiny_COLBITS;
        emask = 1 & (e[epos / 8] >> (epos & 7));
        epart[j / 8] ^= emask << (j & 7);
    }

    for (i = 0; i < mc_mctiny_Y; ++i) {
        tally = 0;
        for (j = 0; j < mc_mctiny_XBYTES; ++j) tally ^= epart[j] & block[j];

        tally ^= tally >> 4;
        tally ^= tally >> 2;
        tally ^= tally >> 1;
        tally &= 1;
        s[i / 8] ^= tally << (i & 7);
        block += mc_mctiny_XBYTES;
    }
}

void mc_mctiny_pieceinit(unsigned char *synd2, const unsigned char *e,
                         long long p) {
    long long i;
    long long epos;
    unsigned char bit;

    for (i = 0; i < mc_mctiny_PIECEBYTES; ++i) synd2[i] = 0;

    for (i = 0; i < mc_mctiny_V * mc_mctiny_Y; ++i) {
        epos = p * mc_mctiny_V * mc_mctiny_Y + i;
        if (epos < 0) continue;
        if (epos >= mc_mctiny_COLBITS) continue;
        bit = 1 & (e[epos / 8] >> (epos & 7));
        synd2[i / 8] ^= bit << (i & 7);
    }
}

void mc_mctiny_pieceabsorb(unsigned char *synd2, const unsigned char *synd1,
                           long long i) {
    long long j;
    long long outpos;
    unsigned char bit;

    if (i < 0) return;
    if (i >= mc_mctiny_V) return;

    for (j = 0; j < mc_mctiny_Y; ++j) {
        bit = 1 & (synd1[j / 8] >> (j & 7));
        outpos = i * mc_mctiny_Y + j;
        synd2[outpos / 8] ^= bit << (outpos & 7);
    }
}

void mc_mctiny_finalize(unsigned char *c, unsigned char *k,
                        const unsigned char *synd3, const unsigned char *e) {
    unsigned char one_ec[1 + mc_mctiny_EBYTES + mc_CIPHERTEXTBYTES] = {1};

    memcpy(c, synd3, mc_mctiny_COLBYTES);
    memcpy(one_ec + 1, e, mc_mctiny_EBYTES);
    memcpy(one_ec + 1 + mc_mctiny_EBYTES, c, mc_mctiny_COLBYTES);
    mceliece_xof_shake256(k, mc_HASHBYTES, one_ec, sizeof one_ec);
}

void mc_mctiny_pk2block(unsigned char *out, const unsigned char *pk,
                        long long rowpos, long long colpos) {
    long long i, j;
    unsigned char bit;

    colpos *= mc_mctiny_X;
    rowpos *= mc_mctiny_Y;

    for (i = 0; i < mc_mctiny_BLOCKBYTES; ++i) out[i] = 0;

    for (i = 0; i < mc_mctiny_Y; ++i) {
        if (rowpos + i < 0) continue;
        if (rowpos + i >= mc_mctiny_COLBITS) continue;

        for (j = 0; j < mc_mctiny_X; ++j) {
            if (colpos + j < 0) continue;
            if (colpos + j >= mc_mctiny_ROWBITS) continue;

            bit = pk[mc_mctiny_ROWBYTES * (rowpos + i) + (colpos + j) / 8];
            bit = 1 & (bit >> ((colpos + j) & 7));
            bit <<= ((i * mc_mctiny_X + j) & 7);
            out[(i * mc_mctiny_X + j) / 8] |= bit;
        }
    }
}

void mc_mctiny_mergepieces(
    unsigned char *synd3,
    unsigned char synd2[mc_mctiny_PIECES][mc_mctiny_PIECEBYTES]) {
    long long i, p, j;
    unsigned char bit;

    for (i = 0; i < mc_mctiny_COLBYTES; ++i) synd3[i] = 0;

    for (p = 0; p < mc_mctiny_PIECES; ++p) {
        for (i = 0; i < mc_mctiny_Y * mc_mctiny_V; ++i) {
            j = p * mc_mctiny_Y * mc_mctiny_V + i;
            if (j >= mc_mctiny_COLBITS) continue;
            bit = 1 & (synd2[p][i / 8] >> (i & 7));
            synd3[j / 8] ^= bit << (j & 7);
        }
    }
}
