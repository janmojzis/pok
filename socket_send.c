#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include "socket.h"

static long long packets = 0;

long long socket_send(int fd, const void *x, long long xlen,
                      const unsigned char *ip, const unsigned char *port) {

    struct sockaddr *sa = 0;
    socklen_t salen = 0;
    struct sockaddr_in6 sa6 = {0};
    long long r;

    if (xlen < 0 || xlen > socket_MAXBYTES) {
        errno = EINVAL;
        return -1;
    }

    if (ip && port) {
        sa6.sin6_family = AF_INET6;
        memcpy(&sa6.sin6_addr, ip, 16);
        memcpy(&sa6.sin6_port, port, 2);
        sa = (struct sockaddr *) &sa6;
        salen = sizeof sa6;
    }

    r = sendto(fd, x, xlen, 0, sa, salen);
    if (xlen > 0 && r > 0) ++packets;
    return r;
}

long long socket_packetssent(void) { return packets; }
