#include <unistd.h>
#include "socket_queue.h"
#include "socket.h"

void socket_close(int fd) {
#ifdef SOCKET_QUEUE
    socket_queue_close_(fd);
#endif
    close(fd);
}
