#include "e.h"
#include "parsehex.h"
#include "log.h"

static int hexdigit(char x) {

    if (x >= '0' && x <= '9') return x - '0';
    if (x >= 'a' && x <= 'f') return 10 + (x - 'a');
    if (x >= 'A' && x <= 'F') return 10 + (x - 'A');
    return -1;
}

int parsehex(unsigned char *yv, long long ylen, const char *xv) {

    unsigned char *y = yv;
    const char *x = xv;
    long long ylenorig = ylen;

    errno = 0;

    if (!x) {
        x = "(null)";
        goto err;
    }

    while (ylen > 0) {
        int digit0;
        int digit1;
        digit0 = hexdigit(x[0]);
        if (digit0 == -1) goto err;
        digit1 = hexdigit(x[1]);
        if (digit1 == -1) goto err;
        *y++ = (unsigned char) (digit1 + 16 * digit0);
        --ylen;
        x += 2;
    }
    if (x[0]) goto err;

    log_t4("'", xv, "' parsed to ", log_hex(yv, y - yv));
    return 1;
err:
    errno = EINVAL;
    log_e5("'", xv, "' is not a ", log_num(ylenorig),
           "-bytes hex. encoded string");
    return 0;
}
