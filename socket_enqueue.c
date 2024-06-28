#include <errno.h>
#include <string.h>
#include "socket_queue.h"
#include "socket.h"

long long socket_enqueue_(int fd, const void *x, long long xlen,
                          const unsigned char *ip, const unsigned char *port) {

    unsigned char ipportspace[18];
    unsigned char *ipport = 0;

    if (xlen < 0 || xlen > socket_MAXBYTES) {
        errno = EINVAL;
        return -1;
    }

    if (ip && port) {
        memcpy(ipportspace, ip, 16);
        memcpy(ipportspace + 16, port, 2);
        ipport = ipportspace;
    }

    if (!socket_queue_enqueue_(fd, x, xlen, ipport)) return -1;
    return xlen;
}
