#ifndef PARSENUM_H____
#define PARSENUM_H____

extern int parsenum_(long long *, long long, long long, const char *);
extern int parsenum(long long *, long long, long long, const char *);

#define parsenum_MIN -9223372036854775807LL /* XXX */
#define parsenum_MAX 9223372036854775807LL

#endif
