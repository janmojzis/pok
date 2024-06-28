/*
20240509
*/

#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include "log.h"
#include "parseip.h"

int parseip(unsigned char *ip, const char *ipstr) {

    if (!ipstr) ipstr = "(null)";

    /* IPv4 */
    if (inet_pton(AF_INET, ipstr, ip + 12) == 1) {
        memcpy(ip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12);
        goto ok;
    }

    /* IPv6 */
    if (inet_pton(AF_INET6, ipstr, ip) == 1) goto ok;

    errno = EINVAL;
    log_e3("'", ipstr, "' is not a valid IP address");
    return 0;

ok:
    log_t4("'", ipstr, "' parsed to ", log_ip(ip));
    return 1;
}
