#include "mc.h"
#include "log.h"
#include "socket.h"
#include "client.h"

void client_send(int fd, const void *xv, long long xlen,
                 const unsigned char *ip, const unsigned char *port) {

    long long p = 0, l = 0;
    char *text = "query";
    const unsigned char *x = (const unsigned char *) xv;

    if (xlen < mc_HEADERBYTES) {
        log_b1("xlen < mc_HEADERBYTES");
        return;
    }
    if (xlen > packet_MAXBYTES) {
        log_b1("xlen > packet_MAXBYTES");
        return;
    }

    if (x[7] == 'L') {
        mc_Levpos_load(&l, &p, 0, x + mc_MAGICBYTES + mc_EXTENSIONBYTES);
        text = "key-download: query";
    }
    if (x[7] == 'K') {
        mc_Levpos_load(&l, &p, 0,
                       x + mc_MAGICBYTES + mc_EXTENSIONBYTES + mc_NONCEBYTES -
                           2);
        text = "key-exchange: query";
    }

    socket_enqueue(fd, x, xlen, ip, port);
    log_t8(text, log_num(l), "/", log_num0(p, 3), " sent ",
           log_ipport(ip, port), ", len = ", log_num(xlen));
}
