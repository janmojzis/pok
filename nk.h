#ifndef _NK_H____
#define _NK_H____

#define nk_KEYS 4 /* must be power of 2 */

extern void nk_cleanup(void);
extern void nk_next(void);
extern void nk_nonce(unsigned char *);
extern int nk_keyid(unsigned char *);
extern void nk_derivekeys(unsigned char *, unsigned char *, unsigned char *,
                          unsigned char *);

#ifdef TEST
extern void nk_nonce_decrypt(unsigned char *);
#endif

#endif
