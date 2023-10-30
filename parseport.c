#include "parsenum.h"
#include "parseport.h"

int parseport(unsigned char *port, const char *portstr) {

    long long num;

    if (!parsenum(&num, 0, 65535, portstr)) return 0;
    port[0] = (unsigned char) (num >> 8);
    port[1] = (unsigned char) (num);
    return 1;
}
