#include "uint16_unpack.h"
#include "uint16_pack.h"
#include "mc.h"

void mc_Levpos_load(long long *l, long long *p, int *f,
                    const unsigned char *x) {
    uint16_t n = uint16_unpack(x);
    *p = n & 0x0fff;
    *l = n >> 13;
    if (f) *f = (n >> 12) & 1;
}

void mc_Levpos_store(unsigned char *o, long long l, long long p, int f) {
    uint16_pack(o, p | (f << 12) | (l << 13));
}
