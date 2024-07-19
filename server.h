#ifndef _SERVER_H____
#define _SERVER_H____

extern long long server_phase0(unsigned char *, long long);
extern long long server_phase1(unsigned char *, long long);
extern long long server_phase2(unsigned char *, long long);
extern long long server_phase3(unsigned char *, unsigned char *, long long);

extern void server_child(unsigned char *, unsigned char *, unsigned char *,
                         unsigned char *, unsigned char *, int, char **,
                         long long);

#endif
