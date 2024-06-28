#include <string.h>
#include "byte.h"

void byte_zero(void *yv, long long ylen) {
    if (ylen > 0) { memset(yv, 0, ylen); }
    __asm__ __volatile__("" : : "r"(yv) : "memory");
}
