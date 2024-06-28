#include "uint32_pack.h"

void uint32_pack(unsigned char *x, uint32_t u) {
    x[0] = u;
    x[1] = u >> 8;
    x[2] = u >> 16;
    x[3] = u >> 24;
}
