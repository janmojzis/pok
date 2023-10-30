#include <time.h>
#include "seconds.h"

double seconds(void) {

    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (double) t.tv_sec + 0.000000001 * (double) t.tv_nsec;
}
