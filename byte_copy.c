#include <string.h>
#include "byte.h"

void byte_copy(void *yv, long long ylen, const void *xv) {
    if (ylen > 0) { memcpy(yv, xv, ylen); }
}
