#include "uint64_unpack.h"

uint64_t uint64_unpack(const unsigned char *x) {
    uint64_t u0 = ((uint64_t) x[0]);
    uint64_t u1 = ((uint64_t) x[1]) << 8;
    uint64_t u2 = ((uint64_t) x[2]) << 16;
    uint64_t u3 = ((uint64_t) x[3]) << 24;
    uint64_t u4 = ((uint64_t) x[4]) << 32;
    uint64_t u5 = ((uint64_t) x[5]) << 40;
    uint64_t u6 = ((uint64_t) x[6]) << 48;
    uint64_t u7 = ((uint64_t) x[7]) << 56;
    return u0 ^ u1 ^ u2 ^ u3 ^ u4 ^ u5 ^ u6 ^ u7;
}
