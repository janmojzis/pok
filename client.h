#ifndef CLIENT_H____
#define CLIENT_H____

#include "packet.h"
#include "mc.h"

#define client_NUMIP 8

/* client_downloadpk.c */
extern int client_downloadpk(struct mc_pktree *pktree, int udpfd,
                             unsigned char *ip, long long iplen,
                             unsigned char *extension, unsigned char *port,
                             unsigned char *pkhash, long long timeout);

/* client_kex.c */
extern int client_kex(int, unsigned char *, long long, unsigned char *,
                      unsigned char *, unsigned char *, unsigned char *,
                      unsigned char *, long long);

/* client_send.c */
extern void client_send(int, const void *, long long, const unsigned char *,
                        const unsigned char *);

/* client_recv.c */
extern long long client_recv(const char *, int, void *, long long,
                             unsigned char *, unsigned char *);

#endif
