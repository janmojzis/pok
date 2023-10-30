#include <arpa/inet.h>
#include <string.h>
#include "e.h"
#include "log.h"
#include "parseip.h"

int parseip6_(unsigned char *ip, const char *ipstr) {

    if (inet_pton(AF_INET6, ipstr, ip) == 1) return 1;
    return 0;
}

int parseip4_(unsigned char *ip, const char *ipstr) {

    if (inet_pton(AF_INET, ipstr, ip + 12) == 1) {
        memcpy(ip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12);
        return 1;
    }
    return 0;
}

int parseip(unsigned char *ip, const char *ipstr) {

    errno = 0;

    if (!ipstr) {
        ipstr = "(null)";
        goto err;
    }

    if (parseip4_(ip, ipstr)) {
        log_t4("'", ipstr, "' parsed to IPv4 ", log_ip(ip));
        return 1;
    }
    if (parseip6_(ip, ipstr)) {
        log_t4("'", ipstr, "' parsed to IPv6 ", log_ip(ip));
        return 1;
    }

err:
    errno = EINVAL;
    log_e3("'", ipstr, "' is not a valid IP address");
    return 0;
}
