#ifndef _DUPFORKEXEC_____
#define _DUPFORKEXEC_____

#include <sys/types.h>

extern pid_t dupforkexec(int *, int *, char **);
extern int dupforkexec_wait(pid_t, char **);

#endif
