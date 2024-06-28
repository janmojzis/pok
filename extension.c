#include "parseip.h"
#include "byte.h"
#include "mc.h"
#include "extension.h"

int extension_parse(unsigned char *y, const char *x) {
    byte_zero(y, mc_proto_EXTENSIONBYTES);
    if (!x || !x[0]) return 1; /* empty extension */
    if (!parseip(y, x)) return 0;
    return 1;
}
