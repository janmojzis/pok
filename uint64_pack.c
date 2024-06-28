#include "uint64_pack.h"

void uint64_pack(unsigned char *x, uint64_t u) {
    x[0] = u;
    x[1] = u >> 8;
    x[2] = u >> 16;
    x[3] = u >> 24;
    x[4] = u >> 32;
    x[5] = u >> 40;
    x[6] = u >> 48;
    x[7] = u >> 56;
}
