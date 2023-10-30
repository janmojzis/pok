/*
taken from nacl-20110221, from from curvecp/open_pipe.c
- reformated using clang-format
- replaced 1 -> FD_CLOEXEC
*/

#include <unistd.h>
#include <fcntl.h>
#include "open.h"
#include "blocking.h"

int open_pipe(int *fd) {
    int i;
    if (pipe(fd) == -1) return -1;
    for (i = 0; i < 2; ++i) {
        fcntl(fd[i], F_SETFD, FD_CLOEXEC);
        blocking_disable(fd[i]);
    }
    return 0;
}
