#ifndef _RESOLVEHOST_H____
#define _RESOLVEHOST_H____

extern long long resolvehost_(unsigned char *, long long, const char *,
                              const char *, unsigned long long);
#define resolvehost(a, b, c) resolvehost_((a), (b), (c), __FILE__, __LINE__)

#endif
