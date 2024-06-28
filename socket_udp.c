#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include "blocking.h"
#include "socket_queue.h"
#include "socket.h"

void ipv6only_disable(int fd) {
#ifdef IPV6_V6ONLY
#ifdef IPPROTO_IPV6
    int opt = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof opt);
#endif
#endif
}

int socket_udp(void) {

    int fd;

    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd == -1) return -1;
#ifdef SOCKET_QUEUE
    if (!socket_queue_create_(fd)) {
        close(fd);
        return -1;
    }
#endif
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    blocking_disable(fd);
    ipv6only_disable(fd);
    return fd;
}
