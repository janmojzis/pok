/*
taken from nacl-20110221, from from curvecp/open_write.c
- reformated using clang-format
- replaced 1 -> FD_CLOEXEC
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "open.h"

int open_write(const char *fn) {
#ifdef O_CLOEXEC
    return open(fn, O_CREAT | O_WRONLY | O_NONBLOCK | O_CLOEXEC, 0644);
#else
    int fd = open(fn, O_CREAT | O_WRONLY | O_NONBLOCK, 0644);
    if (fd == -1) return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
#endif
}
