#include "mc.h"
#include "log.h"
#include "byte.h"
#include "socket.h"
#include "client.h"

long long client_recv(const char *magic, int fd, void *xv, long long xlen,
                      unsigned char *ip, unsigned char *port) {

    long long p = 0, l = 0, r;
    char *text = "reply";
    unsigned char *x = (unsigned char *) xv;

    r = socket_recv(fd, x, xlen, ip, port);
    if (r < 0) {
        if (!socket_temperror()) { log_w1("socket_recv failed"); }
        return r;
    }

    if (r < mc_HEADERBYTES) {
        log_w1("r < mc_HEADERBYTES");
        return -1;
    }
    if (!byte_isequal(x, mc_MAGICBYTES, magic)) {
        log_w1("bad magic");
        return -1;
    }

    if (r > packet_MAXBYTES) {
        log_w1("r > packet_MAXBYTES");
        return -1;
    }

    if (x[7] == 'L') {
        mc_Levpos_load(&l, &p, 0, x + mc_MAGICBYTES + mc_EXTENSIONBYTES);
        text = "key-download: reply";
    }
    if (x[7] == 'K') {
        mc_Levpos_load(&l, &p, 0, x + mc_HEADERBYTES - 2);
        text = "key-exchange: reply";
    }

    log_t8(text, log_num(l), "/", log_num0(p, 3), " recv ",
           log_ipport(ip, port), ", len = ", log_num(r));
    return r;
}
