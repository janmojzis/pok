#ifndef _CRYPTO_BLOCK____
#define _CRYPTO_BLOCK____

#define crypto_block_BYTES 16
#define crypto_block_KEYBYTES 32

extern int crypto_block(unsigned char *, const unsigned char *,
                        const unsigned char *);

extern int crypto_block_decrypt(unsigned char *, const unsigned char *,
                                const unsigned char *);

#endif
