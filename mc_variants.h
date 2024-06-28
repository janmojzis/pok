#ifndef _MC_VARIANTS_H____
#define _MC_VARIANTS_H____

/* WARNING: auto-generated (by mc_variants.py); do not edit */

#include <mceliece.h>

#define mc_proto_MAGICQUERY "PoKv0dQ"
#define mc_proto_MAGICQUERY0 "PoKv0dQ0"
#define mc_proto_MAGICQUERY1 "PoKv0dQ1"
#define mc_proto_MAGICQUERY2 "PoKv0dQ2"
#define mc_proto_MAGICQUERY3 "PoKv0dQ3"
#define mc_proto_MAGICQUERYM "PoKv0dQM"
#define mc_proto_MAGICREPLY "PoKv0dR"
#define mc_proto_MAGICREPLY0 "PoKv0dR0"
#define mc_proto_MAGICREPLY1 "PoKv0dR1"
#define mc_proto_MAGICREPLY2 "PoKv0dR2"
#define mc_proto_MAGICREPLY3 "PoKv0dR3"
#define mc_proto_MAGICREPLYM "PoKv0dRM"
#define mc_proto_MAGICBYTES 8
#define mc_proto_EXTENSIONBYTES 18
#define mc_proto_NONCEBYTES 24
#define mc_proto_HEADERBYTES 50

#define mc_proto_AUTHBYTES 16
#define mc_mctiny_NMAX 8192
#define mc_mctiny_TMAX 128
#define mc_mctiny_VMAX 8
#define mc_mctiny_XBYTESMAX 91
#define mc_mctiny_YBYTESMAX 5
#define mc_mctiny_EBYTESMAX 1024
#define mc_mctiny_BLOCKBYTESMAX 1184
#define mc_mctiny_COOKIEBLOCKBYTESMAX 21
#define mc_mctiny_ROWBLOCKSMAX 128
#define mc_mctiny_COLBLOCKSMAX 18
#define mc_mctiny_PIECESMAX 19
#define mc_mctiny_PIECEBYTESMAX 24
#define mc_mctiny_COLBYTESMAX 208
#define mc_mctiny_QUERY0BYTES 850

struct mc_mctiny {
    long long mmask;
    long long n;
    long long t;
    long long rowbits;
    long long rowbytes;
    long long colbits;
    long long colbytes;
    long long ebytes;
    long long x;
    long long xbytes;
    long long colblocks;
    long long y;
    long long ybytes;
    long long rowblocks;
    long long blockbytes;
    long long v;
    long long pieces;
    long long piecebytes;
    long long cookieblockbytes;
    long long query0bytes;
    long long reply0bytes;
    long long query1bytes;
    long long reply1bytes;
    long long query2bytes;
    long long reply2bytes;
    long long query3bytes;
    long long reply3bytes;
};

#define mc_PUBLICKEYBYTESMAX mceliece8192128pc_PUBLICKEYBYTES
#define mc_SECRETKEYBYTESMAX mceliece8192128pc_SECRETKEYBYTES
#define mc_CIPHERTEXTBYTESMAX mceliece8192128pc_CIPHERTEXTBYTES
#define mc_SESSIONKEYBYTES mceliece8192128pc_BYTES
#define mc_HASHBYTES 32
#define mc_DEFAULTNAME "mceliece6688128"
#define mc_IDMASK 0x70

struct mc {
    const char *name;
    const unsigned char id;
    void (*keypair)(unsigned char *, unsigned char *);
    int (*enc)(unsigned char *, unsigned char *, const unsigned char *);
    int (*dec)(unsigned char *, const unsigned char *, const unsigned char *);
    long long publickeybytes;
    long long secretkeybytes;
    long long ciphertextbytes;
    struct mc_mctiny mctiny;
};

extern struct mc mc_variants[];

#endif
