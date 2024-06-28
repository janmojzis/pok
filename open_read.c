/*
taken from nacl-20110221, from from curvecp/open_read.c
- reformated using clang-format
- replaced 1 -> FD_CLOEXEC
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "open.h"

int open_read(const char *fn) {
#ifdef O_CLOEXEC
    return open(fn, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
#else
    int fd = open(fn, O_RDONLY | O_NONBLOCK);
    if (fd == -1) return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
#endif
}
