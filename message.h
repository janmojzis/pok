#ifndef _MESSAGE_H____
#define _MESSAGE_H____

#include "log.h"

#define message_BLOCKBYTES 1108
#define message_HEADERBYTES 32
#define message_MAXBYTES (message_HEADERBYTES + message_BLOCKBYTES)

#define message_EOF 16384
#define message_FAILURE 32768
#define message_LENMASK 0x3fff

/*
message header:
8B ackstop1
4B ackstart2
2B ackstop2
1B ackstart3
1B ackstop3
1B ackstart4
1B ackstop4
1B ackstart5
1B ackstop5
1B ackstart6
1B ackstop6
8B messageid
2B messagelen | messageof | messagefailure
*/

extern void message(int, char **, long long);

extern void message_log_(const char *, unsigned char *);
#define message_log(a, b)                                                      \
    if (log_level >= log_level_TRACING) { message_log_((a), (b)); }

#endif
