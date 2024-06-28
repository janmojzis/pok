/*
20240210
Jan Mojzis
Public domain.
*/

#include <stdint.h>
#include "crypto_stream_xsalsa20.h"

static inline uint32_t unpack32(const unsigned char *x) {
    uint32_t u0 = ((uint32_t) x[0]);
    uint32_t u1 = ((uint32_t) x[1]) << 8;
    uint32_t u2 = ((uint32_t) x[2]) << 16;
    uint32_t u3 = ((uint32_t) x[3]) << 24;
    return u0 ^ u1 ^ u2 ^ u3;
}

static inline void pack32(unsigned char *x, uint32_t u) {
    x[0] = u;
    x[1] = u >> 8;
    x[2] = u >> 16;
    x[3] = u >> 24;
}

#define ROTATE(x, c) ((x) << (c)) ^ ((x) >> (32 - (c)))

#define QUARTERROUND(a, b, c, d)                                               \
    b ^= ROTATE(d + a, 7);                                                     \
    c ^= ROTATE(a + b, 9);                                                     \
    d ^= ROTATE(b + c, 13);                                                    \
    a ^= ROTATE(c + d, 18)

#define TWOROUNDS()                                                            \
    QUARTERROUND(x0, x4, x8, x12);                                             \
    QUARTERROUND(x5, x9, x13, x1);                                             \
    QUARTERROUND(x10, x14, x2, x6);                                            \
    QUARTERROUND(x15, x3, x7, x11);                                            \
    QUARTERROUND(x0, x1, x2, x3);                                              \
    QUARTERROUND(x5, x6, x7, x4);                                              \
    QUARTERROUND(x10, x11, x8, x9);                                            \
    QUARTERROUND(x15, x12, x13, x14)

#define XORBLOCK(o, i)                                                         \
    x0 = s0;                                                                   \
    x1 = k0;                                                                   \
    x2 = k1;                                                                   \
    x3 = k2;                                                                   \
    x4 = k3;                                                                   \
    x5 = s1;                                                                   \
    x6 = n0;                                                                   \
    x7 = n1;                                                                   \
    x8 = n2;                                                                   \
    x9 = n3;                                                                   \
    x10 = s2;                                                                  \
    x11 = k4;                                                                  \
    x12 = k5;                                                                  \
    x13 = k6;                                                                  \
    x14 = k7;                                                                  \
    x15 = s3;                                                                  \
                                                                               \
    TWOROUNDS(); /* round  1,  2 */                                            \
    TWOROUNDS(); /* round  3,  4 */                                            \
    TWOROUNDS(); /* round  5,  6 */                                            \
    TWOROUNDS(); /* round  7,  8 */                                            \
    TWOROUNDS(); /* round  9, 10 */                                            \
    TWOROUNDS(); /* round 11, 12 */                                            \
    TWOROUNDS(); /* round 13, 14 */                                            \
    TWOROUNDS(); /* round 15, 16 */                                            \
    TWOROUNDS(); /* round 17, 18 */                                            \
    TWOROUNDS(); /* round 19, 20 */                                            \
                                                                               \
    pack32(o, (x0 + s0) ^ unpack32(i));                                        \
    pack32(o + 4, (x1 + k0) ^ unpack32(i + 4));                                \
    pack32(o + 8, (x2 + k1) ^ unpack32(i + 8));                                \
    pack32(o + 12, (x3 + k2) ^ unpack32(i + 12));                              \
    pack32(o + 16, (x4 + k3) ^ unpack32(i + 16));                              \
    pack32(o + 20, (x5 + s1) ^ unpack32(i + 20));                              \
    pack32(o + 24, (x6 + n0) ^ unpack32(i + 24));                              \
    pack32(o + 28, (x7 + n1) ^ unpack32(i + 28));                              \
    pack32(o + 32, (x8 + n2) ^ unpack32(i + 32));                              \
    pack32(o + 36, (x9 + n3) ^ unpack32(i + 36));                              \
    pack32(o + 40, (x10 + s2) ^ unpack32(i + 40));                             \
    pack32(o + 44, (x11 + k4) ^ unpack32(i + 44));                             \
    pack32(o + 48, (x12 + k5) ^ unpack32(i + 48));                             \
    pack32(o + 52, (x13 + k6) ^ unpack32(i + 52));                             \
    pack32(o + 56, (x14 + k7) ^ unpack32(i + 56));                             \
    pack32(o + 60, (x15 + s3) ^ unpack32(i + 60))

#define SUBKEY()                                                               \
    x0 = s0;                                                                   \
    x1 = k0;                                                                   \
    x2 = k1;                                                                   \
    x3 = k2;                                                                   \
    x4 = k3;                                                                   \
    x5 = s1;                                                                   \
    x6 = n0;                                                                   \
    x7 = n1;                                                                   \
    x8 = n2;                                                                   \
    x9 = n3;                                                                   \
    x10 = s2;                                                                  \
    x11 = k4;                                                                  \
    x12 = k5;                                                                  \
    x13 = k6;                                                                  \
    x14 = k7;                                                                  \
    x15 = s3;                                                                  \
                                                                               \
    TWOROUNDS(); /* round  1,  2 */                                            \
    TWOROUNDS(); /* round  3,  4 */                                            \
    TWOROUNDS(); /* round  5,  6 */                                            \
    TWOROUNDS(); /* round  7,  8 */                                            \
    TWOROUNDS(); /* round  9, 10 */                                            \
    TWOROUNDS(); /* round 11, 12 */                                            \
    TWOROUNDS(); /* round 13, 14 */                                            \
    TWOROUNDS(); /* round 15, 16 */                                            \
    TWOROUNDS(); /* round 17, 18 */                                            \
    TWOROUNDS(); /* round 19, 20 */                                            \
                                                                               \
    k0 = x0;                                                                   \
    k1 = x5;                                                                   \
    k2 = x10;                                                                  \
    k3 = x15;                                                                  \
    k4 = x6;                                                                   \
    k5 = x7;                                                                   \
    k6 = x8;                                                                   \
    k7 = x9

int crypto_stream_xsalsa20_xor(unsigned char *c, const unsigned char *m,
                               unsigned long long l, const unsigned char *n,
                               const unsigned char *k) {

    register uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    register uint32_t x8, x9, x10, x11, x12, x13, x14, x15;
    uint32_t k0 = unpack32(k);
    uint32_t k1 = unpack32(k + 4);
    uint32_t k2 = unpack32(k + 8);
    uint32_t k3 = unpack32(k + 12);
    uint32_t k4 = unpack32(k + 16);
    uint32_t k5 = unpack32(k + 20);
    uint32_t k6 = unpack32(k + 24);
    uint32_t k7 = unpack32(k + 28);
    uint32_t n0 = unpack32(n);
    uint32_t n1 = unpack32(n + 4);
    uint32_t n2 = unpack32(n + 8);
    uint32_t n3 = unpack32(n + 12);
    uint32_t s0 = 0x61707865;
    uint32_t s1 = 0x3320646E;
    uint32_t s2 = 0x79622D32;
    uint32_t s3 = 0x6B206574;
    uint64_t u = 0;

    if (!l) return 0;

    SUBKEY();

    n0 = unpack32(n + 16);
    n1 = unpack32(n + 20);
    n2 = 0;
    n3 = 0;

    while (l >= 64) {
        XORBLOCK(c, m);

        n2 = ++u;
        n3 = u >> 32;

        l -= 64;
        c += 64;
        m += 64;
    }
    if (l) {
        unsigned char b[64] = {0};
        unsigned long long j;

        for (j = 0; j < l; ++j) b[j] = m[j];
        XORBLOCK(b, b);
        for (j = 0; j < l; ++j) c[j] = b[j];
    }
    return 0;
}

int crypto_stream_xsalsa20(unsigned char *c, unsigned long long l,
                           const unsigned char *n, const unsigned char *k) {

    unsigned long long j;
    unsigned char ncopy[24], kcopy[32];

    for (j = 0; j < 32; ++j) kcopy[j] = k[j];
    for (j = 0; j < 24; ++j) ncopy[j] = n[j];
    for (j = 0; j < l; ++j) c[j] = 0;
    return crypto_stream_xsalsa20_xor(c, c, l, ncopy, kcopy);
}
