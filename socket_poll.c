#include <sys/select.h>
#include <sys/socket.h>
#include <errno.h>
#include "log.h"
#include "socket_queue.h"
#include "socket.h"

int socket_poll_and_dequeue_(struct pollfd *x, nfds_t len, int millisecs) {

    struct timeval *tvp = 0;
    struct timeval tv;
    fd_set rfds, wfds;
    nfds_t nfds, i;
    int fd, r;
    struct socket_queue_ *q = socket_queue_head_;

#if 0
    log_t5("socket_poll(len = ", log_num(len),
           ", millisecs = ", log_num(millisecs), ")");
#endif

    for (i = 0; i < len; ++i) x[i].revents = 0;

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    nfds = 1;

    for (q = socket_queue_head_; q; q = q->next) {
        if (!q->tail) continue;
        fd = q->fd;
        if (fd < 0) continue;
        if ((unsigned int) fd >= (8 * sizeof(fd_set))) continue;
        if ((unsigned int) fd >= nfds) nfds = fd + 1;
        FD_SET(fd, &wfds);
    }

    for (i = 0; i < len; ++i) {
        fd = x[i].fd;
        if (fd < 0) continue;
        if ((unsigned int) fd >= (8 * sizeof(fd_set))) continue;
        if ((unsigned int) fd >= nfds) nfds = fd + 1;
        if (x[i].events & POLLIN) FD_SET(fd, &rfds);
        if (x[i].events & POLLOUT) FD_SET(fd, &wfds);
    }

    if (millisecs >= 0) {
        tv.tv_sec = millisecs / 1000;
        tv.tv_usec = 1000 * (millisecs % 1000);
        tvp = &tv;
    }

    r = select(nfds, &rfds, &wfds, (fd_set *) 0, tvp);
    if (r <= 0) goto cleanup;

    for (q = socket_queue_head_; q; q = q->next) {
        if (!q->tail) continue;
        fd = q->fd;
        if (fd < 0) continue;
        if ((unsigned int) fd >= (8 * sizeof(fd_set))) continue;
        if (!FD_ISSET(fd, &wfds)) continue;
        while (q->tail) {
            unsigned char *ip = 0;
            unsigned char *port = 0;
            if (q->tail->ipport) {
                ip = q->tail->ipport;
                port = q->tail->ipport + 16;
            }
            if (socket_send(fd, q->tail->data, q->tail->datalen, ip, port) ==
                -1) {
                if (socket_temperror()) break;
                log_w1("dropping datagram from the socket_queue");
            }
            socket_queue_dequeue_(q);
        }
    }

    r = 0;
    for (i = 0; i < len; ++i) {
        fd = x[i].fd;
        if (fd < 0) continue;
        if ((unsigned int) fd >= (8 * sizeof(fd_set))) continue;

        if (x[i].events & POLLIN) {
            if (FD_ISSET(fd, &rfds)) {
                x[i].revents |= POLLIN;
                ++r;
            }
        }
        if (x[i].events & POLLOUT) {
            if (FD_ISSET(fd, &wfds)) {
                x[i].revents |= POLLOUT;
                ++r;
            }
        }
    }

    if (r == 0) {
        errno = EAGAIN;
        r = -1;
    }

cleanup:
#if 0
    log_t6("socket_poll(len = ", log_num(len),
           ", millisecs = ", log_num(millisecs), ") = ", log_num(r));
#endif
    return r;
}
