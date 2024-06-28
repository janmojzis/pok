#include "uint16_pack.h"

void uint16_pack(unsigned char *x, uint16_t u) {
    x[0] = u;
    x[1] = u >> 8;
}
