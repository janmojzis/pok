/*
Jan Mojzis
20240210

A bitsliced implementation of AES-256.
.
Implementation strategy based on work Adomnicai/Peyrin
https://eprint.iacr.org/2020/1123.pdf.
And uses Boyar/Peralta/Calik AES sbox circuit
https://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt
.
This bitsliced variant allows to perform operations on two 128bit blocks
in parallel. The implementation takes advantage of this by doing SubBytes
for key expansion and encryption at the same time.
*/

#include <stdint.h>
#include "crypto_block.h"

typedef uint32_t uint32x8_t[8];

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

#define RR(x, c) ((x) >> (c)) ^ ((x) << (32 - (c)))

#define SWAPMOVE(a, b, m, n)                                                   \
    do {                                                                       \
        uint32_t t = (b ^ (a >> n)) & m;                                       \
        b ^= t;                                                                \
        a ^= (t << n);                                                         \
    } while (0)

/* pack two blocks to the bitsliced form */
static void bs_pack2(uint32_t *bs_out, const unsigned char *in0,
                     const unsigned char *in1) {

    bs_out[0] = unpack32(in0);
    bs_out[1] = unpack32(in1);
    bs_out[2] = unpack32(in0 + 4);
    bs_out[3] = unpack32(in1 + 4);
    bs_out[4] = unpack32(in0 + 8);
    bs_out[5] = unpack32(in1 + 8);
    bs_out[6] = unpack32(in0 + 12);
    bs_out[7] = unpack32(in1 + 12);

    SWAPMOVE(bs_out[1], bs_out[0], 0x55555555, 1);
    SWAPMOVE(bs_out[3], bs_out[2], 0x55555555, 1);
    SWAPMOVE(bs_out[5], bs_out[4], 0x55555555, 1);
    SWAPMOVE(bs_out[7], bs_out[6], 0x55555555, 1);
    SWAPMOVE(bs_out[2], bs_out[0], 0x33333333, 2);
    SWAPMOVE(bs_out[3], bs_out[1], 0x33333333, 2);
    SWAPMOVE(bs_out[6], bs_out[4], 0x33333333, 2);
    SWAPMOVE(bs_out[7], bs_out[5], 0x33333333, 2);
    SWAPMOVE(bs_out[4], bs_out[0], 0x0f0f0f0f, 4);
    SWAPMOVE(bs_out[5], bs_out[1], 0x0f0f0f0f, 4);
    SWAPMOVE(bs_out[6], bs_out[2], 0x0f0f0f0f, 4);
    SWAPMOVE(bs_out[7], bs_out[3], 0x0f0f0f0f, 4);
}

/* unpack one block from the bitsliced form */
static void bs_unpack(unsigned char *out0, uint32_t *bs_in) {

    SWAPMOVE(bs_in[4], bs_in[0], 0x0f0f0f0f, 4);
    SWAPMOVE(bs_in[5], bs_in[1], 0x0f0f0f0f, 4);
    SWAPMOVE(bs_in[6], bs_in[2], 0x0f0f0f0f, 4);
    SWAPMOVE(bs_in[7], bs_in[3], 0x0f0f0f0f, 4);
    SWAPMOVE(bs_in[2], bs_in[0], 0x33333333, 2);
    SWAPMOVE(bs_in[3], bs_in[1], 0x33333333, 2);
    SWAPMOVE(bs_in[6], bs_in[4], 0x33333333, 2);
    SWAPMOVE(bs_in[7], bs_in[5], 0x33333333, 2);
    SWAPMOVE(bs_in[1], bs_in[0], 0x55555555, 1);
    SWAPMOVE(bs_in[3], bs_in[2], 0x55555555, 1);
    SWAPMOVE(bs_in[5], bs_in[4], 0x55555555, 1);
    SWAPMOVE(bs_in[7], bs_in[6], 0x55555555, 1);

    pack32(out0, bs_in[0]);
    pack32(out0 + 4, bs_in[2]);
    pack32(out0 + 8, bs_in[4]);
    pack32(out0 + 12, bs_in[6]);
}

/*
AddRoundKey:
input: [state, 0x0] [key1, key2]
output: [new state, key2] [key1, key2]
.
xor the state with the round key1 and
insert keys2 to the bs_state
*/
static inline void bs_addroundkey(uint32_t *bs_state, uint32_t *bs_key) {

    bs_state[0] ^= bs_key[0];
    bs_state[1] ^= bs_key[1];
    bs_state[2] ^= bs_key[2];
    bs_state[3] ^= bs_key[3];
    bs_state[4] ^= bs_key[4];
    bs_state[5] ^= bs_key[5];
    bs_state[6] ^= bs_key[6];
    bs_state[7] ^= bs_key[7];
}

/*
SubBytes:
input: [state, key2]
output: [new state, new key2]
*/
static void bs_subbytes(uint32_t *bs_state) {

    uint32_t U0 = bs_state[0];
    uint32_t U1 = bs_state[1];
    uint32_t U2 = bs_state[2];
    uint32_t U3 = bs_state[3];
    uint32_t U4 = bs_state[4];
    uint32_t U5 = bs_state[5];
    uint32_t U6 = bs_state[6];
    uint32_t U7 = bs_state[7];

    uint32_t y14 = U3 ^ U5;
    uint32_t y13 = U0 ^ U6;
    uint32_t y9 = U0 ^ U3;
    uint32_t y8 = U0 ^ U5;
    uint32_t t0 = U1 ^ U2;
    uint32_t y1 = t0 ^ U7;
    uint32_t y4 = y1 ^ U3;
    uint32_t y12 = y13 ^ y14;
    uint32_t y2 = y1 ^ U0;
    uint32_t y5 = y1 ^ U6;
    uint32_t y3 = y5 ^ y8;
    uint32_t t1 = U4 ^ y12;
    uint32_t y15 = t1 ^ U5;
    uint32_t y20 = t1 ^ U1;
    uint32_t y6 = y15 ^ U7;
    uint32_t y10 = y15 ^ t0;
    uint32_t y11 = y20 ^ y9;
    uint32_t y7 = U7 ^ y11;
    uint32_t y17 = y10 ^ y11;
    uint32_t y19 = y10 ^ y8;
    uint32_t y16 = t0 ^ y11;
    uint32_t y21 = y13 ^ y16;
    uint32_t y18 = U0 ^ y16;
    uint32_t t2 = y12 & y15;
    uint32_t t3 = y3 & y6;
    uint32_t t4 = t3 ^ t2;
    uint32_t t5 = y4 & U7;
    uint32_t t6 = t5 ^ t2;
    uint32_t t7 = y13 & y16;
    uint32_t t8 = y5 & y1;
    uint32_t t9 = t8 ^ t7;
    uint32_t t10 = y2 & y7;
    uint32_t t11 = t10 ^ t7;
    uint32_t t12 = y9 & y11;
    uint32_t t13 = y14 & y17;
    uint32_t t14 = t13 ^ t12;
    uint32_t t15 = y8 & y10;
    uint32_t t16 = t15 ^ t12;
    uint32_t t17 = t4 ^ y20;
    uint32_t t18 = t6 ^ t16;
    uint32_t t19 = t9 ^ t14;
    uint32_t t20 = t11 ^ t16;
    uint32_t t21 = t17 ^ t14;
    uint32_t t22 = t18 ^ y19;
    uint32_t t23 = t19 ^ y21;
    uint32_t t24 = t20 ^ y18;
    uint32_t t25 = t21 ^ t22;
    uint32_t t26 = t21 & t23;
    uint32_t t27 = t24 ^ t26;
    uint32_t t28 = t25 & t27;
    uint32_t t29 = t28 ^ t22;
    uint32_t t30 = t23 ^ t24;
    uint32_t t31 = t22 ^ t26;
    uint32_t t32 = t31 & t30;
    uint32_t t33 = t32 ^ t24;
    uint32_t t34 = t23 ^ t33;
    uint32_t t35 = t27 ^ t33;
    uint32_t t36 = t24 & t35;
    uint32_t t37 = t36 ^ t34;
    uint32_t t38 = t27 ^ t36;
    uint32_t t39 = t29 & t38;
    uint32_t t40 = t25 ^ t39;
    uint32_t t41 = t40 ^ t37;
    uint32_t t42 = t29 ^ t33;
    uint32_t t43 = t29 ^ t40;
    uint32_t t44 = t33 ^ t37;
    uint32_t t45 = t42 ^ t41;
    uint32_t z0 = t44 & y15;
    uint32_t z1 = t37 & y6;
    uint32_t z2 = t33 & U7;
    uint32_t z3 = t43 & y16;
    uint32_t z4 = t40 & y1;
    uint32_t z5 = t29 & y7;
    uint32_t z6 = t42 & y11;
    uint32_t z7 = t45 & y17;
    uint32_t z8 = t41 & y10;
    uint32_t z9 = t44 & y12;
    uint32_t z10 = t37 & y3;
    uint32_t z11 = t33 & y4;
    uint32_t z12 = t43 & y13;
    uint32_t z13 = t40 & y5;
    uint32_t z14 = t29 & y2;
    uint32_t z15 = t42 & y9;
    uint32_t z16 = t45 & y14;
    uint32_t z17 = t41 & y8;
    uint32_t tc1 = z15 ^ z16;
    uint32_t tc2 = z10 ^ tc1;
    uint32_t tc3 = z9 ^ tc2;
    uint32_t tc4 = z0 ^ z2;
    uint32_t tc5 = z1 ^ z0;
    uint32_t tc6 = z3 ^ z4;
    uint32_t tc7 = z12 ^ tc4;
    uint32_t tc8 = z7 ^ tc6;
    uint32_t tc9 = z8 ^ tc7;
    uint32_t tc10 = tc8 ^ tc9;
    uint32_t tc11 = tc6 ^ tc5;
    uint32_t tc12 = z3 ^ z5;
    uint32_t tc13 = z13 ^ tc1;
    uint32_t tc14 = tc4 ^ tc12;
    uint32_t S3 = tc3 ^ tc11;
    uint32_t tc16 = z6 ^ tc8;
    uint32_t tc17 = z14 ^ tc10;
    uint32_t tc18 = tc13 ^ tc14;
    uint32_t S7 = z12 ^ tc18 ^ 0xffffffff;
    uint32_t tc20 = z15 ^ tc16;
    uint32_t tc21 = tc2 ^ z11;
    uint32_t S0 = tc3 ^ tc16;
    uint32_t S6 = tc10 ^ tc18 ^ 0xffffffff;
    uint32_t S4 = tc14 ^ S3;
    uint32_t S1 = S3 ^ tc16 ^ 0xffffffff;
    uint32_t tc26 = tc17 ^ tc20;
    uint32_t S2 = tc26 ^ z17 ^ 0xffffffff;
    uint32_t S5 = tc21 ^ tc17;

    bs_state[0] = S0;
    bs_state[1] = S1;
    bs_state[2] = S2;
    bs_state[3] = S3;
    bs_state[4] = S4;
    bs_state[5] = S5;
    bs_state[6] = S6;
    bs_state[7] = S7;
}

/*
ShiftRows:
input: [state, <ballast>]
output: [new state, <ballast>]
*/
static void bs_shiftrows(uint32_t *bs_state) {

    SWAPMOVE(bs_state[0], bs_state[0], 0x020a0800, 4);
    SWAPMOVE(bs_state[1], bs_state[1], 0x020a0800, 4);
    SWAPMOVE(bs_state[2], bs_state[2], 0x020a0800, 4);
    SWAPMOVE(bs_state[3], bs_state[3], 0x020a0800, 4);
    SWAPMOVE(bs_state[4], bs_state[4], 0x020a0800, 4);
    SWAPMOVE(bs_state[5], bs_state[5], 0x020a0800, 4);
    SWAPMOVE(bs_state[6], bs_state[6], 0x020a0800, 4);
    SWAPMOVE(bs_state[7], bs_state[7], 0x020a0800, 4);

    SWAPMOVE(bs_state[0], bs_state[0], 0x22002200, 2);
    SWAPMOVE(bs_state[1], bs_state[1], 0x22002200, 2);
    SWAPMOVE(bs_state[2], bs_state[2], 0x22002200, 2);
    SWAPMOVE(bs_state[3], bs_state[3], 0x22002200, 2);
    SWAPMOVE(bs_state[4], bs_state[4], 0x22002200, 2);
    SWAPMOVE(bs_state[5], bs_state[5], 0x22002200, 2);
    SWAPMOVE(bs_state[6], bs_state[6], 0x22002200, 2);
    SWAPMOVE(bs_state[7], bs_state[7], 0x22002200, 2);
}

/*
MixColumns:
input: [state, <ballast>]
output: [new state, 0x0]
*/
static void bs_mixcolumns(uint32_t *state) {

    uint32_t S0 = state[0], S0r8 = RR(S0, 8), S0r16_S0r24 = RR(S0 ^ S0r8, 16);
    uint32_t S1 = state[1], S1r8 = RR(S1, 8), S1r16_S1r24 = RR(S1 ^ S1r8, 16);
    uint32_t S2 = state[2], S2r8 = RR(S2, 8), S2r16_S2r24 = RR(S2 ^ S2r8, 16);
    uint32_t S3 = state[3], S3r8 = RR(S3, 8), S3r16_S3r24 = RR(S3 ^ S3r8, 16);
    uint32_t S4 = state[4], S4r8 = RR(S4, 8), S4r16_S4r24 = RR(S4 ^ S4r8, 16);
    uint32_t S5 = state[5], S5r8 = RR(S5, 8), S5r16_S5r24 = RR(S5 ^ S5r8, 16);
    uint32_t S6 = state[6], S6r8 = RR(S6, 8), S6r16_S6r24 = RR(S6 ^ S6r8, 16);
    uint32_t S7 = state[7], S7r8 = RR(S7, 8), S7r16_S7r24 = RR(S7 ^ S7r8, 16);
    state[0] = 0xaaaaaaaa & (S1 ^ S1r8 ^ S0r8 ^ S0r16_S0r24);
    state[1] = 0xaaaaaaaa & (S2 ^ S2r8 ^ S1r8 ^ S1r16_S1r24);
    state[2] = 0xaaaaaaaa & (S3 ^ S3r8 ^ S2r8 ^ S2r16_S2r24);
    state[3] = 0xaaaaaaaa & (S4 ^ S4r8 ^ S3r8 ^ S3r16_S3r24 ^ S0 ^ S0r8);
    state[4] = 0xaaaaaaaa & (S5 ^ S5r8 ^ S4r8 ^ S4r16_S4r24 ^ S0 ^ S0r8);
    state[5] = 0xaaaaaaaa & (S6 ^ S6r8 ^ S5r8 ^ S5r16_S5r24);
    state[6] = 0xaaaaaaaa & (S7 ^ S7r8 ^ S6r8 ^ S6r16_S6r24 ^ S0 ^ S0r8);
    state[7] = 0xaaaaaaaa & (S0 ^ S0r8 ^ S7r8 ^ S7r16_S7r24);
}

/*
xor key columns + swap keys
input: ([state, key2], [key0, key1])
output: ([state, <ballast>], [key1, new key2])
*/
static void bs_xorcolumnsswap(uint32_t *bs_state, uint32_t *bs_key, int r) {

    long long i;
    uint32x8_t bs_key2;

    for (i = 0; i < 8; ++i) {
        bs_key2[i] = ((RR(bs_state[i], r) ^ ((bs_key[i]) >> 1)) & 0x40404040);
        bs_key2[i] ^= (((bs_key2[i] >> 2) ^ ((bs_key[i]) >> 1)) & 0x10101010);
        bs_key2[i] ^= (((bs_key2[i] >> 2) ^ ((bs_key[i]) >> 1)) & 0x04040404);
        bs_key2[i] ^= (((bs_key2[i] >> 2) ^ ((bs_key[i]) >> 1)) & 0x01010101);
    }

    for (i = 0; i < 8; ++i) {
        bs_key[i] = ((bs_key[i] << 1) & 0xaaaaaaaa) ^ (bs_key2[i]);
    }
}

static unsigned char zero[16] = {0};

int crypto_block(unsigned char *out, const unsigned char *in,
                 const unsigned char *key) {

    uint32x8_t bs_state; /* holds state and next round key2 */
    uint32x8_t bs_key;   /* holds previous round key0 and current round key1 */

    /* bs_key = [key0, key1], note: here key2 = key1 */
    bs_pack2(bs_key, key, key + 16);

    /* bs_state = [state, 0x0] */
    bs_pack2(bs_state, in, zero);

    /* AddRoundKey */
    /* bs_state = [state ^ key0, 0x0 ^ key2], note: here key2 = key1 */
    bs_addroundkey(bs_state, bs_key);

    for (long long r = 0; r < 14; ++r) {

        /* SubBytes + KeyExpansion */
        /* bs_state = SubBytes([state, key2]) */
        bs_subbytes(bs_state);
        /* key2 ^= rcon */
        if (r % 2 == 0) bs_state[7 - (r + 1) / 2] ^= 0x00000100;
        /* bs_key = SubWord/RotWord([<ballast>, key2], [key0, key1]) */
        /* bs_key = swap(bs_key) */
        if (r % 2 == 0) bs_xorcolumnsswap(bs_state, bs_key, 2);
        if (r % 2 == 1) bs_xorcolumnsswap(bs_state, bs_key, 26);
        /* note: here bs_key holds [key1, key2] */
        /* note: here bs_state holds [state, <ballast>] */

        /* ShiftRows */
        /* bs_state = ShiftRows([state, <ballast>]) */
        bs_shiftrows(bs_state);

        /* MixColumns */
        if (r < 13) {
            /* bs_state = MixColumns([state, <ballast>]) */
            bs_mixcolumns(bs_state);
            /* note: here bs_state holds [state, 0x0] */
        }

        /* AddRoundKey */
        /* bs_state = [state ^ key1, 0x0 ^ key2] */
        bs_addroundkey(bs_state, bs_key);
    }

    /* store output */
    bs_unpack(out, bs_state);

    return 0;
}
