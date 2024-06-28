#ifndef _CLIENT_H____
#define _CLIENT_H____

#include <stdint.h>
#include "packet.h"
#include "mc.h"
#include "extension.h"
#include "pacing.h"

#define client_NUMIP 8

struct client_connection {
    int fd;
    long long iplen;
    unsigned char ip[16 * client_NUMIP];
    unsigned char port[2];
    unsigned char serverpkhash[mc_HASHBYTES];
    unsigned char serverauthpkhash[mc_HASHBYTES];
    unsigned char extension[mc_proto_EXTENSIONBYTES];
    unsigned char clientkey[packet_KEYBYTES];
    unsigned char serverkey[packet_KEYBYTES];

    unsigned char id[16];

    unsigned char nonce[mc_proto_NONCEBYTES];
    uint64_t servernonce;
    uint64_t clientnonce;
    double receivedtm;

    struct mc mc;
};

extern int client_connect(struct client_connection *c, long long timeout);

#if 0
struct client_connection {
    int fd;
    unsigned char ip[16];
    unsigned char port[2];
    unsigned char serverpkhash[mc_HASHBYTES];
    unsigned char serverauthpkhash[mc_HASHBYTES];
    unsigned char extension[packet_EXTENSIONBYTES];
    unsigned char clientkey[packet_KEYBYTES];
    unsigned char serverkey[packet_KEYBYTES];
    unsigned char id[16]; /* nonce */
    uint64_t servernonce;
    double receivedtm;
    uint64_t clientnonce;
}
#endif

struct client {

    /* socket */
    int fd;

    /* packet */
    unsigned char packetip[16];
    unsigned char packetport[2];

    /* extension */
    unsigned char extension[mc_proto_EXTENSIONBYTES];

    /* server */
    long long serveriplen;
    long long serverippos;
    unsigned char serverip[16 * client_NUMIP];
    unsigned char serverport[2];
    unsigned char serverpkhash[mc_HASHBYTES];
    unsigned char serverauthpkhash[mc_HASHBYTES];

    /* pacing */
    struct pacing_connection pacingc;
    struct pacing_packet pacing0;
    struct pacing_packet pacing1[mc_mctiny_ROWBLOCKSMAX]
                                [mc_mctiny_COLBLOCKSMAX];
    struct pacing_packet pacing2[mc_mctiny_PIECESMAX];
    struct pacing_packet pacing3;
    int flagreply0;
    int flagreply1[mc_mctiny_ROWBLOCKSMAX][mc_mctiny_COLBLOCKSMAX];
    int flagreply2[mc_mctiny_PIECESMAX];
    int flagcookie9;

    /* mctiny */
    unsigned char query0[mc_mctiny_QUERY0BYTES];
    unsigned char block[mc_mctiny_BLOCKBYTESMAX];
    unsigned char cookie1[mc_mctiny_ROWBLOCKSMAX][mc_mctiny_COLBLOCKSMAX]
                         [mc_mctiny_COOKIEBLOCKBYTESMAX];
    unsigned char blankcookie1[mc_mctiny_COOKIEBLOCKBYTESMAX];
    unsigned char synd2[mc_mctiny_PIECESMAX][mc_mctiny_PIECEBYTESMAX];
    unsigned char synd3[mc_mctiny_COLBYTESMAX];
    unsigned char cookie9[56]; /* XXX */

    unsigned char ciphertext[mc_CIPHERTEXTBYTESMAX];
    unsigned char clientpk[mc_PUBLICKEYBYTESMAX];
    unsigned char clientsk[mc_SECRETKEYBYTESMAX];
    unsigned char longtermnonce[mc_proto_NONCEBYTES];
    unsigned char nonce[mc_proto_NONCEBYTES];
    unsigned char key0[3 * packet_KEYBYTES];
    unsigned char key123[packet_KEYBYTES];
    unsigned char key[2 * packet_KEYBYTES];

    /* mc */
    struct mc mc;
};

extern int client_query0_isready(struct client *);
extern void client_query0_prepare(struct client *);
extern void client_query0_do(struct client *);
extern void client_reply0(struct client *, unsigned char *, long long);

extern int client_query1_isready(struct client *, long long, long long);
extern void client_query1(struct client *, long long, long long);
extern void client_reply1(struct client *, unsigned char *, long long);

extern int client_query2_isready(struct client *, long long);
extern void client_query2(struct client *, long long);
extern void client_reply2(struct client *, unsigned char *, long long);

extern int client_query3_isready(struct client *);
extern void client_query3(struct client *);
extern void client_reply3(struct client *, unsigned char *, long long);

extern void client_queryM(struct client_connection *, unsigned char *,
                          long long);
extern long long client_replyM(struct client_connection *, unsigned char *,
                               unsigned char *, long long);

#endif
