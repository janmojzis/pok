#ifndef _MC_H____
#define _MC_H____

#include "mc_variants.h"

/* mc.c */
extern int mc_parse(struct mc *, const char *);
extern int mc_fromsksize(struct mc *, long long);
extern int mc_frompksize(struct mc *, long long);
extern int mc_fromid(struct mc *, unsigned char);

extern void mc_keypair(struct mc *, unsigned char *, long long, unsigned char *,
                       unsigned char *);
extern void mc_enc(struct mc *, unsigned char *, unsigned char *,
                   const unsigned char *);
extern void mc_dec(struct mc *, unsigned char *, const unsigned char *,
                   const unsigned char *);

/* mc_mctiny.c */
extern int mc_mctiny_seedisvalid(struct mc *, const unsigned char *);
extern void mc_mctiny_seed2e(struct mc *, unsigned char *,
                             const unsigned char *);
extern void mc_mctiny_eblock2syndrome(struct mc *, unsigned char *,
                                      const unsigned char *,
                                      const unsigned char *, long long);
extern void mc_mctiny_pieceinit(struct mc *, unsigned char *,
                                const unsigned char *, long long);
extern void mc_mctiny_pieceabsorb(struct mc *, unsigned char *,
                                  const unsigned char *, long long);
extern void mc_mctiny_finalize(struct mc *, unsigned char *, unsigned char *,
                               const unsigned char *, const unsigned char *);
extern void mc_mctiny_pk2block(struct mc *, unsigned char *,
                               const unsigned char *, long long, long long);
extern void
mc_mctiny_mergepieces(struct mc *, unsigned char *,
                      const unsigned char (*)[mc_mctiny_PIECEBYTESMAX]);

/* mc_keys.c */
extern void mc_keys_dec(unsigned char *, const unsigned char *,
                        const unsigned char *);
extern void mc_keys_enc(unsigned char *, unsigned char *,
                        const unsigned char *);
extern int mc_keys_authenc(unsigned char *, unsigned char *,
                           const unsigned char *);
extern void mc_keys_authdec(unsigned char *, const unsigned char *,
                            const unsigned char *);
extern int mc_keys(unsigned char *, long long, const char *);

#endif
