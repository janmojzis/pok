#include "parseip.h"
#include "parseport.h"
#include "byte.h"
#include "mc.h"
#include "extension.h"

int extension_parse(unsigned char *y, const char *x) {
    byte_zero(y, mc_proto_EXTENSIONBYTES);
    if (!x || !x[0]) return 1; /* empty extension */
    char ipstr[64];
    long long i;

    for (i = 0; i < (long long) sizeof ipstr; ++i) {
        ipstr[i] = x[i];
        if (x[i] == ':') {
            ipstr[i] = 0;
            if (!parseport(y + 16, x + i + 1)) return 0;
            if (!parseip(y, ipstr)) return 0;
            return 1;
        }
        if (x[i] == 0) {
            if (!parseip(y, ipstr)) return 0;
            return 1;
        }
    }
    return 0;
}
