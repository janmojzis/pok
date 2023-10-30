## POK - 'Post-Quantum OverKill' client/server encryption tool
It is a tool that creates an encrypted and authenticated connection
between a network client and a server. The connection is established
using UDP packets, which are encrypted by the XSalsa20 algorithm and
authenticated by the Poly1305 algorithm.

A variant of the [McTiny protocol](https://mctiny.org/) is used for key exchange, which uses
[Classic Mceliece cryptosystem](https://classic.mceliece.org/) encryption system with `overkill` parameter set 8192128,
hence the name `Post-quantum OverKill` `POK`.
