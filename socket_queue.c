#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "log.h"
#include "socket_queue.h"

struct socket_queue_ *socket_queue_head_ = 0;

int socket_queue_create_(int fd) {

    struct socket_queue_ *r;

    r = malloc(sizeof(*r));
    if (!r) return 0;
    memset(r, 0, sizeof(*r));
    r->fd = fd;
    r->next = socket_queue_head_;
    socket_queue_head_ = r;

    return 1;
}

static struct socket_queue_ *socket_queue_get_(int fd) {

    struct socket_queue_ *r;

    for (r = socket_queue_head_; r; r = r->next) {
        if (r->fd == fd) return r;
    }
    return 0;
}

static void socket_queue_drop_(int fd) {

    struct socket_queue_record_ *tail;
    struct socket_queue_ *q = socket_queue_get_(fd);

    if (!q) return;

    do {
        tail = q->tail;
        socket_queue_dequeue_(q);
    } while (tail);
}

void socket_queue_close_(int fd) {

    struct socket_queue_ *r = socket_queue_head_, *prev = 0;

    socket_queue_drop_(fd);

    if (r && r->fd == fd) {
        socket_queue_head_ = r->next;
        memset(r, 0, sizeof(*r));
        free(r);
        return;
    }

    while (r && r->fd != fd) {
        prev = r;
        r = r->next;
    }

    if (!r) {
        log_b3("can't remove filedescriptor ", log_num(fd),
               " from the socket_queue");
        return;
    }
    prev->next = r->next;
    memset(r, 0, sizeof(*r));
    free(r);
}

#define pointer(x, xlen) ((unsigned char *) (x) + (xlen))

int socket_queue_enqueue_(int fd, const void *data, long long datalen,
                          unsigned char *ipport) {

    struct socket_queue_record_ *r, *head;
    struct socket_queue_ *q = socket_queue_get_(fd);
    long long ipportlen = 0;
    if (ipport) ipportlen = 18;

    if (!q) {
        errno = EINVAL;
        return 0;
    }

    /* check queue length */
    if (q->len >= socket_queue_MAXLEN) {
        errno = EAGAIN;
        return 0;
    }

    /* allocate space */
    r = malloc(sizeof(*r) + datalen + ipportlen);
    if (!r) {
        errno = EAGAIN;
        return 0;
    }

    /* copy data */
    r->datalen = datalen;
    r->data = (unsigned char *) pointer(r, sizeof(*r));
    memcpy(r->data, data, r->datalen);

    /* copy sockaddr structure */
    r->ipportlen = ipportlen;
    r->ipport = 0;
    if (r->ipportlen) {
        r->ipport = pointer(r, sizeof(*r) + datalen);
        memcpy(r->ipport, ipport, r->ipportlen);
    }

    /* add to linked list */
    r->next = 0;
    if (q->head) {
        head = q->head;
        head->next = r;
    }
    q->head = r;
    if (!q->tail) q->tail = r;
    ++q->len;

    return 1;
}

void socket_queue_dequeue_(struct socket_queue_ *q) {

    struct socket_queue_record_ *tail = q->tail;
    if (!tail) return;

    /* remove from linked list */
    q->tail = tail->next;
    if (!q->tail) q->head = 0;
    --q->len;

    /* free space */
    memset(tail, 0, sizeof(*tail) + tail->datalen + tail->ipportlen);
    free(tail);
}
