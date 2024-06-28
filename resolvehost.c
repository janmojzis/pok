#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include "e.h"
#include "log.h"
#include "randommod.h"
#include "resolvehost.h"

static void swap(unsigned char *x, unsigned char *y) {

    unsigned char t[16];

    memcpy(t, x, 16);
    memcpy(x, y, 16);
    memcpy(y, t, 16);
}

static void sortip(unsigned char *s, long long nn) {

    long long i;
    long long n = nn;

    if (nn < 0) return;

    /* randomize IP's */
    n >>= 4;
    while (n > 1) {
        i = randommod(n);
        --n;
        swap(s + 16 * i, s + 16 * n);
    }

    /* add IPv6 first */
    for (i = 0; i + 16 <= nn; i += 16) {
        if (memcmp(s + i, "\0\0\0\0\0\0\0\0\0\0\377\377", 12)) {
            swap(s + i, s);
            break;
        }
    }
}

long long resolvehost(unsigned char *ip, long long iplen, const char *host) {

    int err;
    long long i;
    struct addrinfo *res, *res0 = 0, hints;
    long long len = -1;

    if (!ip || iplen < 16 || !host) {
        errno = EINVAL;
        if (!ip) log_b1("resolvehost() called with ip = (null)");
        if (iplen < 16) log_b1("resolvehost() called with iplen < 16");
        if (!host) log_b1("resolvehost() called with host = (null)");
        return -1;
    }

    errno = 0;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_CANONNAME;

    err = getaddrinfo(host, 0, &hints, &res0);
    if (err) {
        log_t6("getaddrinfo(host = ", host, ") = ", gai_strerror(err),
               ", errno = ", e_str(errno));
        /*
        XXX
        getaddrinfo returns EAI_NONAME even in case of system errors,
        e.g. when RLIMIT_NOFILE is set to 0
        */
        if (err == EAI_NONAME) len = 0;
#ifdef EAI_NODATA
        if (err == EAI_NODATA) len = 0;
#endif
        goto done;
    }

    len = 0;
    for (res = res0; res; res = res->ai_next) {
        if (res->ai_addrlen == sizeof(struct sockaddr_in)) {
            if (len + 16 <= iplen) {
                memcpy(ip + len, "\0\0\0\0\0\0\0\0\0\0\377\377", 12);
                memcpy(ip + len + 12,
                       &((struct sockaddr_in *) res->ai_addr)->sin_addr, 4);
                len += 16;
            }
        }
        if (res->ai_addrlen == sizeof(struct sockaddr_in6)) {
            if (len + 16 <= iplen) {
                memcpy(ip + len,
                       &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr, 16);
                len += 16;
            }
        }
    }
    if (len > 0) {
        sortip(ip, len);
        for (i = 0; i < iplen - len; ++i) ip[len + i] = ip[i];
        errno = 0;
    }
done:
    if (res0) freeaddrinfo(res0);

    for (i = 0; i < len; i += 16) {
        log_d5("'", host, "' resolved, ip = '", log_ip(ip + i), "'");
    }
    if (len < 0) log_e3("'", host, "' not resolved:");
    if (len == 0) log_e3("'", host, "' not found");
    return len;
}
