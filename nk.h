#ifndef NK_H____
#define NK_H____

extern void nk_cleanup(void);
extern void nk_next(void);
extern void nk_nonce(unsigned char *);
extern int nk_keyid(unsigned char *);
extern void nk_derivekeys(unsigned char *, unsigned char *, unsigned char *,
                          unsigned char *, unsigned char *, unsigned char *);

#ifdef TEST
extern void nk_nonce_decrypt(unsigned char *);
#endif

#endif
