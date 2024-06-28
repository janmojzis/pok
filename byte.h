/*
taken from nacl-20110221, from curvecp/byte.h
- reformated using clang-format
*/

#ifndef _BYTE_H____
#define _BYTE_H____

extern void byte_copy(void *, long long, const void *);
extern void byte_zero(void *, long long);
extern int byte_isequal(const void *, long long, const void *);

#endif
