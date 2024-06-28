#ifndef _SOCKET_QUEUE_H____
#define _SOCKET_QUEUE_H____

#define socket_queue_MAXLEN 1024

struct socket_queue_record_ {
    struct socket_queue_record_ *next;
    unsigned char *data;
    long long datalen;
    unsigned char *ipport;
    long long ipportlen;
};

struct socket_queue_ {
    struct socket_queue_ *next;
    struct socket_queue_record_ *head;
    struct socket_queue_record_ *tail;
    int fd;
    long long len;
};

extern struct socket_queue_ *socket_queue_head_;

extern int socket_queue_create_(int);
extern void socket_queue_close_(int);

extern int socket_queue_enqueue_(int, const void *, long long, unsigned char *);
extern void socket_queue_dequeue_(struct socket_queue_ *);

#endif
