/* WARNING: auto-generated (by mc.py); do not edit */
#ifndef mc_H____
#define mc_H____

#include <mceliece.h>

#define mc_HASHBYTES 32
#define mc_KEYBYTES 32
#define mc_AUTHBYTES 16
#define mc_MAGICBYTES 8
#define mc_NONCEBYTES 24
#define mc_EXTENSIONBYTES 32
#define mc_HEADERBYTES 64
#define mc_NAME "mceliece6688128"
#define mc_MAGICPREFIX "PoKv0d"
#define mc_MAGICQUERY "PoKv0dQ"
#define mc_MAGICQUERYL "PoKv0dQL"
#define mc_MAGICQUERYK "PoKv0dQK"
#define mc_MAGICREPLY "PoKv0dR"
#define mc_MAGICREPLYL "PoKv0dRL"
#define mc_MAGICREPLYK "PoKv0dRK"

/* mceliece: */
#define mc_PUBLICKEYBYTES mceliece6688128_PUBLICKEYBYTES
#define mc_SECRETKEYBYTES mceliece6688128_SECRETKEYBYTES
#define mc_CIPHERTEXTBYTES mceliece6688128_CIPHERTEXTBYTES
#define mc_SESSIONKEYBYTES mceliece6688128_BYTES
#define mc_keypair mceliece6688128_keypair
#define mc_keypairf mceliece6688128f_keypair
#define mc_enc mceliece6688128_enc
#define mc_dec mceliece6688128_dec

/* mctiny: */
#define mc_mctiny_M 13
#define mc_mctiny_MMASK 8191
#define mc_mctiny_N 6688
#define mc_mctiny_T 128
#define mc_mctiny_ROWBITS 5024
#define mc_mctiny_ROWBYTES 628
#define mc_mctiny_COLBITS 1664
#define mc_mctiny_COLBYTES 208
#define mc_mctiny_EBYTES 836
#define mc_mctiny_X 504
#define mc_mctiny_XBYTES 63
#define mc_mctiny_COLBLOCKS 10
#define mc_mctiny_Y 18
#define mc_mctiny_YBYTES 3
#define mc_mctiny_ROWBLOCKS 93
#define mc_mctiny_BLOCKBYTES 1134
#define mc_mctiny_V 2
#define mc_mctiny_PIECES 47
#define mc_mctiny_PIECEBYTES 5
#define mc_mctiny_P3PIECES 3
#define mc_mctiny_P3BLOCKS 16

#define mc_mctiny_BLOCKS (mc_mctiny_ROWBLOCKS * mc_mctiny_COLBLOCKS)
#define mc_mctiny_COOKIE1BLOCKBYTES 51
#define mc_mctiny_COOKIE2BLOCKBYTES 53
#define mc_mctiny_COOKIE3BLOCKBYTES 128
#define mc_mctiny_COOKIE9BYTES 104

/* pktree: */
#define mc_pktree_L1BLOCKBYTES 96
#define mc_pktree_L2BLOCKBYTES 512
#define mc_pktree_L2BLOCKS 3
#define mc_pktree_L3BLOCKBYTES 640
#define mc_pktree_L3BLOCKS 47
#define mc_pktree_L4BLOCKBYTES mc_mctiny_BLOCKBYTES
#define mc_pktree_L4BLOCKS (mc_mctiny_ROWBLOCKS * mc_mctiny_COLBLOCKS)

#define mc_mctiny_QUERYK0BYTES 832
#define mc_mctiny_REPLYK0BYTES 144
#define mc_mctiny_QUERYK1BYTES 1214
#define mc_mctiny_REPLYK1BYTES 131
#define mc_mctiny_QUERYK2BYTES 1100
#define mc_mctiny_REPLYK2BYTES 133
#define mc_mctiny_QUERYK3BYTES 928
#define mc_mctiny_REPLYK3BYTES 208
#define mc_mctiny_QUERYK4BYTES 848
#define mc_mctiny_REPLYK4BYTES 600

#define mc_pktree_QUERYLBYTES 1232

struct mc_pktree {
    unsigned char l4[mc_pktree_L4BLOCKS][mc_pktree_L4BLOCKBYTES];
    unsigned char l3[mc_pktree_L3BLOCKS][mc_pktree_L3BLOCKBYTES];
    unsigned char l2[mc_pktree_L2BLOCKS][mc_pktree_L2BLOCKBYTES];
    unsigned char l1[mc_pktree_L1BLOCKBYTES];
    unsigned char l0[mc_HASHBYTES];
};

/* mc_mctiny.c */
extern int mc_mctiny_seedisvalid(const unsigned char *);
extern void mc_mctiny_pk2block(unsigned char *, const unsigned char *,
                               long long, long long);
extern void mc_mctiny_seed2e(unsigned char *, const unsigned char *);
extern void mc_mctiny_eblock2syndrome(unsigned char *s, const unsigned char *e,
                                      const unsigned char *, long long);
extern void mc_mctiny_pieceinit(unsigned char *, const unsigned char *,
                                long long);
extern void mc_mctiny_pieceabsorb(unsigned char *, const unsigned char *,
                                  long long);
extern void mc_mctiny_finalize(unsigned char *, unsigned char *,
                               const unsigned char *, const unsigned char *);
extern void
mc_mctiny_mergepieces(unsigned char *,
                      unsigned char[mc_mctiny_PIECES][mc_mctiny_PIECEBYTES]);

/* mc_pktree.c */
extern void mc_pktree_pk2tree(struct mc_pktree *, const unsigned char *);
extern int mc_pktree_block_put(struct mc_pktree *, long long, long long,
                               unsigned char *, long long);
extern long long mc_pktree_block_get(struct mc_pktree *, unsigned char *,
                                     long long, long long);
extern void mc_pktree_to_pk(struct mc_pktree *, unsigned char *);

/* mc_levpos.c */
extern void mc_Levpos_load(long long *, long long *, int *,
                           const unsigned char *);
extern void mc_Levpos_store(unsigned char *, long long, long long, int);

/* mc_keys.c */
extern int mc_keys_loadpk(unsigned char *, const unsigned char *);
extern void mc_keys_dec(unsigned char *, const unsigned char *,
                        const unsigned char *);
/* mc_derivekeys.c */
extern void mc_derivekeys(unsigned char *, unsigned char *,
                          const unsigned char *);

#endif
