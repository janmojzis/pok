#ifndef _SOCKET_H____
#define _SOCKET_H____

#include <poll.h>

#define socket_MAXBYTES 8972 /* space for IPv4 jumbo datagram (MTU 9000) */
#define socket_IPBYTES 16    /* space for IPv6 address */
#define socket_PORTBYTES 2

extern int socket_udp(void);
extern int socket_pair(int *);
extern void socket_close(int);
extern int socket_bind(int, const unsigned char *, const unsigned char *);
extern long long socket_send(int, const void *, long long,
                             const unsigned char *, const unsigned char *);
extern long long socket_recv(int, void *, long long, unsigned char *,
                             unsigned char *);
extern long long socket_packetssent(void);
extern long long socket_packetsreceived(void);
extern int socket_temperror(void);

#ifndef SOCKET_QUEUE
#define socket_enqueue socket_send
#define socket_poll_and_dequeue poll
#else
extern long long socket_enqueue_(int, const void *, long long,
                                 const unsigned char *, const unsigned char *);
extern int socket_poll_and_dequeue_(struct pollfd *, nfds_t, int);
#define socket_enqueue socket_enqueue_
#define socket_poll_and_dequeue socket_poll_and_dequeue_
#endif

#endif
