#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include "blocking.h"
#include "socket_queue.h"
#include "socket.h"

int socket_pair(int *fd) {

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fd) == -1) return -1;
#ifdef SOCKET_QUEUE
    if (!socket_queue_create_(fd[0])) {
        close(fd[0]);
        close(fd[1]);
        return -1;
    }
    if (!socket_queue_create_(fd[1])) {
        socket_close(fd[0]);
        close(fd[1]);
        return -1;
    }
#endif
    fcntl(fd[0], F_SETFD, FD_CLOEXEC);
    fcntl(fd[1], F_SETFD, FD_CLOEXEC);
    blocking_disable(fd[0]);
    blocking_disable(fd[1]);
    return 0;
}
