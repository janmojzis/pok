#include <stdlib.h>
#include "e.h"
#include "log.h"
#include "parsenum.h"

int parsenum_(long long *num, long long min, long long max, const char *str) {

    char *endptr = 0;
    long long out;

    if (!str) return 0;
    if (!str[0]) return 0;

    out = strtoll(str, &endptr, 10);

    if (!endptr) return 0;
    if (endptr[0]) return 0;
    if (out < min) return 0;
    if (out > max) return 0;

    *num = out;
    return 1;
}

int parsenum(long long *num, long long min, long long max, const char *str) {

    if (!str) {
        str = "(null)";
        goto err;
    }
    if (!str[0]) goto err;
    if (!parsenum_(num, min, max, str)) goto err;

    errno = 0;
    log_t4("'", log_str(str), "' parsed to ", log_num(*num));
    return 1;

err:
    errno = EINVAL;
    log_e7("'", log_str(str), "' is not a number in the range <", log_num(min),
           ",", log_num(max), ">");
    return 0;
}
