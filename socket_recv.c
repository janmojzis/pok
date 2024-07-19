#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include "socket.h"

static long long packets = 0;

long long socket_recv(int fd, void *x, long long xlen, unsigned char *ip,
                      unsigned char *port) {

    struct sockaddr_storage sa = {0};
    socklen_t salen = sizeof sa;
    long long r;

    if (xlen < 0) {
        errno = EINVAL;
        return -1;
    }

    if (xlen > socket_MAXBYTES) xlen = socket_MAXBYTES + 1;

    r = recvfrom(fd, x, xlen, 0, (struct sockaddr *) &sa, &salen);
    if (r == -1) return -1;

    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) &sa;
        if (ip) {
            memcpy(ip, "\0\0\0\0\0\0\0\0\0\0\377\377", 12);
            memcpy(ip + 12, &sin->sin_addr, 4);
        }
        if (port) memcpy(port, &sin->sin_port, 2);
    }
    else if (sa.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &sa;
        if (ip) memcpy(ip, &sin6->sin6_addr, 16);
        if (port) memcpy(port, &sin6->sin6_port, 2);
    }
    else {
        if (ip) memset(ip, 0, 16);
        if (port) memset(port, 0, 2);
    }

    if (r < 0) return -1;
    ++packets;
    return r;
}

long long socket_packetsreceived(void) { return packets; }
