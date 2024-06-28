#include <errno.h>
#include "socket.h"

int socket_temperror(void) {

    if (errno == EINTR) return 1;
    if (errno == EAGAIN) return 1;
    if (errno == ENOBUFS) return 1;
    if (errno == EWOULDBLOCK) return 1;
    return 0;
}
