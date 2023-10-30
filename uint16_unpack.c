#include "uint16_unpack.h"

uint16_t uint16_unpack(const unsigned char *x) {
    uint16_t u0 = ((uint16_t) x[0]);
    uint16_t u1 = ((uint16_t) x[1]) << 8;
    return u0 ^ u1;
}
