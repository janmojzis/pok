#include <time.h>
#include "seconds.h"

double seconds(void) {

    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec + 0.000000001 * t.tv_nsec;
}
