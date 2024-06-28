#include <string.h>
#include "message.h"
#include "uint64_unpack.h"
#include "uint32_unpack.h"
#include "uint16_unpack.h"
#include "uint8_unpack.h"
#include "log.h"

static long long _add_num(char *s, unsigned long long u) {
    long long len = 1;
    unsigned long long q = u;

    while (q > 9) {
        ++len;
        q /= 10;
    }
    if (s) {
        s += len;
        do {
            *--s = '0' + (u % 10);
            u /= 10;
        } while (u);
    }
    return len;
}

static long long _add_str(char *y, const char *x) {
    long long i;
    for (i = 0; x[i]; ++i) y[i] = x[i];
    return i;
}

void message_log_(const char *x, unsigned char *buf) {

    uint64_t stop1, start2, stop2, start3, stop3, start4;
    uint64_t stop4, start5, stop5, start6, stop6;
    uint64_t messageid;
    uint16_t messagelen, messageeof;
    const char *text1, *text2;
    char ackspace[300];
    long long pos;

    stop1 = uint64_unpack(buf);
    start2 = stop1 + uint32_unpack(buf + 8);
    stop2 = start2 + uint16_unpack(buf + 12);
    start3 = stop2 + uint8_unpack(buf + 14);
    stop3 = start3 + uint8_unpack(buf + 15);
    start4 = stop3 + uint8_unpack(buf + 16);
    stop4 = start4 + uint8_unpack(buf + 17);
    start5 = stop4 + uint8_unpack(buf + 18);
    stop5 = start5 + uint8_unpack(buf + 19);
    start6 = stop5 + uint8_unpack(buf + 20);
    stop6 = start6 + uint8_unpack(buf + 21);

    pos = _add_str(ackspace, ", <0-");
    pos += _add_num(ackspace + pos, stop1);
    pos += _add_str(ackspace + pos, ">, <");
    pos += _add_num(ackspace + pos, start2);
    pos += _add_str(ackspace + pos, "-");
    pos += _add_num(ackspace + pos, stop2);
    pos += _add_str(ackspace + pos, ">, <");
    pos += _add_num(ackspace + pos, start3);
    pos += _add_str(ackspace + pos, "-");
    pos += _add_num(ackspace + pos, stop3);
    pos += _add_str(ackspace + pos, ">, <");
    pos += _add_num(ackspace + pos, start4);
    pos += _add_str(ackspace + pos, "-");
    pos += _add_num(ackspace + pos, stop4);
    pos += _add_str(ackspace + pos, ">, <");
    pos += _add_num(ackspace + pos, start5);
    pos += _add_str(ackspace + pos, "-");
    pos += _add_num(ackspace + pos, stop5);
    pos += _add_str(ackspace + pos, ">, <");
    pos += _add_num(ackspace + pos, start6);
    pos += _add_str(ackspace + pos, "-");
    pos += _add_num(ackspace + pos, stop6);
    ackspace[pos] = 0;

    messageid = uint64_unpack(buf + 22);
    messagelen = uint16_unpack(buf + 30);
    messageeof = messagelen & message_EOF;
    messagelen = messagelen & message_LENMASK;

    if (messageeof) {
        if (!messagelen) text2 = ">, eof, len = ";
        if (messagelen) text2 = ">, data+eof, len = ";
    }
    else {
        if (!messagelen) text2 = ">, ack/ping, len = ";
        if (messagelen) text2 = ">, data, len = ";
    }
    if (!strcmp(x, "received")) text1 = "in-message received,      id = ";
    if (!strcmp(x, "old")) text1 = "in-message received OLD,  id = ";
    if (!strcmp(x, "dropped")) text1 = "in-message dropped,       id = ";
    if (!strcmp(x, "written")) text1 = "in-message written,       id = ";
    if (!strcmp(x, "delivered")) text1 = "out-message delivered,    id = ";
    if (!strcmp(x, "readed")) text1 = "out-message readed,       id = ";
    if (!strcmp(x, "transmitted")) text1 = "out-message transmitted,  id = ";
    if (!strcmp(x, "acknowledged")) text1 = "out-message acknowledged, id = ";

    log_t5(text1, log_num(messageid), ackspace, text2, log_num(messagelen));
}
