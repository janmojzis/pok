#ifndef SERVER_H____
#define SERVER_H____

/* key-download */
extern long long server_phaseL(unsigned char *, long long);

/* key-exchange */
extern long long server_phaseK(unsigned char *, long long);
extern long long server_phaseK0(unsigned char *);
extern long long server_phaseK1(unsigned char *, long long, int);
extern long long server_phaseK2(unsigned char *, long long, int);
extern long long server_phaseK3(unsigned char *, long long, int);
extern long long server_phaseK4(unsigned char *);

#endif
