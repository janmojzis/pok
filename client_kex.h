#ifndef CLIENT_KEX____
#define CLIENT_KEX____

#include "mc.h"
#include "socket.h"
#include "packet.h"
#include "pacing.h"
#include "client.h"

struct client_kex {
    struct pacing_connection pacingc;
    struct pacing_packet pacing0[client_NUMIP];
    struct pacing_packet pacing1[2][mc_mctiny_BLOCKS];
    struct pacing_packet pacing2[2][mc_mctiny_PIECES];
    struct pacing_packet pacing3[2][mc_mctiny_P3PIECES];
    struct pacing_packet pacing4;
    int flagreply0;
    int flagreply1[2][mc_mctiny_BLOCKS];
    int flagreply2[2][mc_mctiny_PIECES];
    int flagreply3[2][mc_mctiny_P3PIECES];
    int flagreply4;

    unsigned char ciphertext[mc_CIPHERTEXTBYTES];
    unsigned char ciphertext0[mc_CIPHERTEXTBYTES];
    unsigned char ciphertext1[mc_CIPHERTEXTBYTES];
    unsigned char block[mc_mctiny_BLOCKBYTES];
    unsigned char clientpk[mc_PUBLICKEYBYTES];
    unsigned char clientsk[mc_SECRETKEYBYTES];
    unsigned char authpk[mc_PUBLICKEYBYTES];
    unsigned char authsk[mc_SECRETKEYBYTES];
    unsigned char authpkhash[mc_HASHBYTES];

    unsigned char *pkhash;
    unsigned char *pk;
    unsigned char *extension;
    int fd;
    unsigned char *ip;
    long long iplen;
    unsigned char *port;

    unsigned char packet[packet_MAXBYTES + 1];
    unsigned char packetip[socket_IPBYTES];
    unsigned char packetport[socket_PORTBYTES];
    long long packetlen;

    unsigned char query0[mc_mctiny_QUERYK0BYTES];
    unsigned char cookie1[2][mc_mctiny_BLOCKS][mc_mctiny_COOKIE1BLOCKBYTES];
    unsigned char blankcookie1[mc_mctiny_COOKIE1BLOCKBYTES];
    unsigned char cookie2[2][mc_mctiny_PIECES][mc_mctiny_COOKIE2BLOCKBYTES];
    unsigned char cookie3[2][mc_mctiny_P3PIECES][mc_mctiny_COOKIE3BLOCKBYTES];
    unsigned char cookie9[mc_mctiny_COOKIE9BYTES];

    unsigned char key0query[packet_KEYBYTES];
    unsigned char key0reply[2 * packet_KEYBYTES];
    unsigned char key1234query[packet_KEYBYTES];
    unsigned char key1234reply[packet_KEYBYTES];
    unsigned char key9[2 * packet_KEYBYTES];

    unsigned char longtermnonce[mc_NONCEBYTES];

    struct mc_pktree pktree;
};

extern int client_kex_query0_isready(struct client_kex *);
extern void client_kex_query0_prepare(struct client_kex *);
extern void client_kex_query0(struct client_kex *, long long);
extern void client_kex_reply0(struct client_kex *, unsigned char *, long long,
                              unsigned char *);

extern int client_kex_query1_isready(struct client_kex *, long long, int);
extern void client_kex_query1(struct client_kex *, long long, int);
extern void client_kex_reply1(struct client_kex *, unsigned char *, long long,
                              unsigned char *, long long, int);

extern int client_kex_query2_isready(struct client_kex *, long long, int);
extern void client_kex_query2(struct client_kex *, long long, int);
extern void client_kex_reply2(struct client_kex *, unsigned char *, long long,
                              unsigned char *, long long, int);

extern int client_kex_query3_isready(struct client_kex *, long long, int);
extern void client_kex_query3(struct client_kex *, long long, int);
extern void client_kex_reply3(struct client_kex *, unsigned char *, long long,
                              unsigned char *, long long, int);

extern int client_kex_query4_isready(struct client_kex *);
extern void client_kex_query4(struct client_kex *);
extern void client_kex_reply4(struct client_kex *, unsigned char *, long long,
                              unsigned char *);

#endif
