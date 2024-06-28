#include <stdlib.h>
#include "log.h"
#include "parsenum.h"

int parsenum(long long *num, long long min, long long max, const char *str) {

    char *endptr = 0;
    long long out;

    if (!str) {
        str = "(null)";
        goto err;
    }
    if (!str[0]) goto err;

    out = strtoll(str, &endptr, 10);

    if (!endptr) goto err;
    if (endptr[0]) goto err;
    if (out < min) goto err;
    if (out > max) goto err;

    *num = out;
    log_t4("'", str, "' parsed to ", log_num(*num));
    return 1;

err:
    log_e7("'", str, "' is not a number in the range <", log_num(min), ",",
           log_num(max), ">");
    return 0;
}
