#include "uint32_unpack.h"

uint32_t uint32_unpack(const unsigned char *x) {
    uint32_t u0 = ((uint32_t) x[0]);
    uint32_t u1 = ((uint32_t) x[1]) << 8;
    uint32_t u2 = ((uint32_t) x[2]) << 16;
    uint32_t u3 = ((uint32_t) x[3]) << 24;
    return u0 ^ u1 ^ u2 ^ u3;
}
