/*
taken from nacl-20110221, from from curvecp/open_cwd.c
- reformated using clang-format
- replaced 1 -> FD_CLOEXEC
*/

#include "open.h"

int open_cwd(void) { return open_read("."); }
