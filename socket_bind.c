#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include "socket.h"

int socket_bind(int fd, const unsigned char *ip, const unsigned char *port) {

    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;
    memcpy(&sa.sin6_addr, ip, 16);
    memcpy(&sa.sin6_port, port, 2);
    return bind(fd, (struct sockaddr *) &sa, sizeof sa);
}
