#ifndef _SERVER_H____
#define _SERVER_H____

#include <unistd.h>
#include <stdint.h>
#include "extension.h"
#include "mc.h"
#include "packet.h"

struct server_activeclient {
    pid_t child;
    int s;
    unsigned char clientip[16];
    unsigned char clientport[2];
    unsigned char extension[mc_proto_EXTENSIONBYTES];
    unsigned char clientkey[packet_KEYBYTES];
    unsigned char serverkey[packet_KEYBYTES];
    uint64_t clientnonce;
    uint64_t servernonce;
    double receivedtm;
    unsigned char nonce[packet_NONCEBYTES];
};

extern long long server_phase0(unsigned char *, long long);
extern long long server_phase1(unsigned char *, long long);
extern long long server_phase2(unsigned char *, long long);
extern long long server_phase3(unsigned char *, unsigned char *, long long);

extern long long server_replyM(struct server_activeclient *, unsigned char *,
                               unsigned char *, long long);
extern long long server_queryM(struct server_activeclient *, unsigned char *,
                               unsigned char *, long long, unsigned char *,
                               unsigned char *, unsigned char *);

#endif
