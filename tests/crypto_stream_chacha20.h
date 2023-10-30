#ifndef crypto_stream_chacha20_H
#define crypto_stream_chacha20_H

#define crypto_stream_chacha20_KEYBYTES 32
#define crypto_stream_chacha20_NONCEBYTES 8
extern int crypto_stream_chacha20(unsigned char *, unsigned long long,
                                  const unsigned char *, const unsigned char *);
extern int crypto_stream_chacha20_xor(unsigned char *, const unsigned char *,
                                      unsigned long long, const unsigned char *,
                                      const unsigned char *);

#endif
