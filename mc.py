#!/usr/bin/env python3

# mceliece parameters:

m = 13
n = 6688
t = 128

# mctiny parameters:

x = 504
y = 18
v = 2

# other parameters
keybytes = 32
noncebytes = 24
hashbytes = 32
authbytes = 16
magicbytes = 8
extensionbytes = 32
headerbytes = magicbytes + extensionbytes + noncebytes
p = 1232

# protocol
magicprefix = 'PoKv0d'
magicquery = magicprefix + 'Q'
magicqueryL = magicquery + 'L'
magicqueryK = magicquery + 'K'
magicreply = magicprefix + 'R'
magicreplyL = magicreply + 'L'
magicreplyK = magicreply + 'K'

# mceliece parameter requirements:

assert m >= 1
assert n >= 1
assert t >= 2
assert n <= 2**m

# mctiny parameter requirements:

assert x > 0
assert y > 0
assert v > 0
assert x%8 == 0

# derived parameters:

rows = t*m # number of rows in public key
cols = n-rows # number of columns in public key
rowbytes = (cols+7)//8 # number of bytes in one row
colbytes = (rows+7)//8 # number of bytes in one column
ebytes = (n+7)//8 # number of bytes in error vector

xbytes = (x+7)//8
colblocks = (cols+x-1)//x
ybytes = (y+7)//8
rowblocks = (rows+y-1)//y
blockbytes = xbytes*y

pieces = (rows+v*y-1)//(v*y) # separately delivered pieces of syndrome
piecebytes = (v*y+7)//8 # bytes per piece of syndrome; final piece may be shorter

ciphertextbytes = colbytes

# cookie0 not used
cookie0bytes = 0

# cookieblock holds one block's contribution to ciphertext:
# 16-byte authenticator, y-bit synd1, public-key hash
cookie1blockbytes = authbytes + ybytes + hashbytes

# cookie2block
cookie2blockbytes = authbytes + hashbytes + piecebytes

# cookie9 holds session key + authorization key hash:
# 16-byte authenticator, 32-byte ksession, 32-byte authorization hash, 24-byte nonce
cookie9bytes = authbytes + keybytes + hashbytes + noncebytes

# overhead in each packet:
universal = magicbytes + extensionbytes + noncebytes + authbytes

# p3pieces
p3pieces = (pieces * cookie2blockbytes + p - universal - 1) // (p - universal)
p3blocks = (pieces + p3pieces - 1) // p3pieces

# cookie3block
cookie3blockbytes = authbytes + hashbytes + piecebytes * p3blocks

# pktree blocks
l1blockbytes = hashbytes * p3pieces
l2blockbytes = hashbytes * p3blocks
l2blocks = (l1blockbytes + hashbytes - 1) / hashbytes
l3blockbytes = hashbytes * ((rowblocks * colblocks + pieces - 1) // pieces)
l3blocks = pieces
l4blockbytes = blockbytes
l4blocks = rowblocks * colblocks

# box L
queryLbytes = p

# box K
queryK0bytes = universal+ciphertextbytes+hashbytes+512 # 32-byte serverpkhash, 512-byte extensions
replyK0bytes = universal+cookie0bytes+keybytes+keybytes # two 32-byte encrypted keys
queryK1bytes = universal+cookie0bytes+blockbytes
replyK1bytes = universal+cookie0bytes+cookie1blockbytes
queryK2bytes = universal+cookie0bytes+v*colblocks*cookie1blockbytes
replyK2bytes = universal+cookie0bytes+cookie2blockbytes
queryK3bytes = universal+cookie0bytes+p3blocks*cookie2blockbytes
replyK3bytes = universal+cookie0bytes+cookie3blockbytes
queryK4bytes = universal+cookie0bytes+2*p3pieces*cookie3blockbytes
replyK4bytes = universal+cookie9bytes+2*ciphertextbytes

# derived parameter requirements:

assert colblocks <= 32
assert rowblocks <= 128

#assert queryK0bytes <= p
#assert replyK0bytes <= p
#assert query1bytes <= p
#assert reply1bytes <= p
#assert query2bytes <= p
#assert reply2bytes <= p
#assert query3bytes <= p
#assert reply3bytes <= p

warning='/* WARNING: auto-generated (by mc.py); do not edit */\n'
hfile = warning
hfile += '#ifndef mc_H____\n'
hfile += '#define mc_H____\n'
hfile += '\n'
hfile += '#include <mceliece.h>\n'
hfile += '\n'
hfile += '#define mc_HASHBYTES %d\n' % (hashbytes)
hfile += '#define mc_KEYBYTES %d\n' % (keybytes)
hfile += '#define mc_AUTHBYTES %d\n' % (authbytes)
hfile += '#define mc_MAGICBYTES %d\n' % (magicbytes)
hfile += '#define mc_NONCEBYTES %d\n' % (noncebytes)
hfile += '#define mc_EXTENSIONBYTES %d\n' % (extensionbytes)
hfile += '#define mc_HEADERBYTES %d\n' % (headerbytes)
hfile += '#define mc_NAME "mceliece%d%d"\n' % (n, t)
hfile += '#define mc_MAGICPREFIX "%s"\n' % (magicprefix)
hfile += '#define mc_MAGICQUERY "%s"\n' % (magicquery)
hfile += '#define mc_MAGICQUERYL "%s"\n' % (magicqueryL)
hfile += '#define mc_MAGICQUERYK "%s"\n' % (magicqueryK)
hfile += '#define mc_MAGICREPLY "%s"\n' % (magicreply)
hfile += '#define mc_MAGICREPLYL "%s"\n' % (magicreplyL)
hfile += '#define mc_MAGICREPLYK "%s"\n' % (magicreplyK)
hfile += '\n'
hfile += '/* mceliece: */\n'
hfile += '#define mc_PUBLICKEYBYTES mceliece%d%d_PUBLICKEYBYTES\n' % (n,t)
hfile += '#define mc_SECRETKEYBYTES mceliece%d%d_SECRETKEYBYTES\n' % (n,t)
hfile += '#define mc_CIPHERTEXTBYTES mceliece%d%d_CIPHERTEXTBYTES\n' % (n,t)
hfile += '#define mc_SESSIONKEYBYTES mceliece%d%d_BYTES\n' % (n,t)
hfile += '#define mc_keypair mceliece%d%d_keypair\n' % (n,t)
hfile += '#define mc_keypairf mceliece%d%df_keypair\n' % (n,t)
hfile += '#define mc_enc mceliece%d%d_enc\n' % (n,t)
hfile += '#define mc_dec mceliece%d%d_dec\n' % (n,t)
hfile += '\n'
hfile += '/* mctiny: */\n'
hfile += '#define mc_mctiny_M %d\n' % m
hfile += '#define mc_mctiny_MMASK %d\n' % ((2**m)-1)
hfile += '#define mc_mctiny_N %d\n' % n
hfile += '#define mc_mctiny_T %d\n' % t
hfile += '#define mc_mctiny_ROWBITS %d\n' % cols
hfile += '#define mc_mctiny_ROWBYTES %d\n' % rowbytes
hfile += '#define mc_mctiny_COLBITS %d\n' % rows
hfile += '#define mc_mctiny_COLBYTES %d\n' % colbytes
hfile += '#define mc_mctiny_EBYTES %d\n' % ebytes
hfile += '#define mc_mctiny_X %d\n' % x
hfile += '#define mc_mctiny_XBYTES %d\n' % xbytes
hfile += '#define mc_mctiny_COLBLOCKS %d\n' % colblocks
hfile += '#define mc_mctiny_Y %d\n' % y
hfile += '#define mc_mctiny_YBYTES %d\n' % ybytes
hfile += '#define mc_mctiny_ROWBLOCKS %d\n' % rowblocks
hfile += '#define mc_mctiny_BLOCKBYTES %d\n' % blockbytes
hfile += '#define mc_mctiny_V %d\n' % v
hfile += '#define mc_mctiny_PIECES %d\n' % pieces
hfile += '#define mc_mctiny_PIECEBYTES %d\n' % piecebytes
hfile += '#define mc_mctiny_P3PIECES %d\n' % (p3pieces)
hfile += '#define mc_mctiny_P3BLOCKS %d\n' % (p3blocks)
hfile += '\n'
hfile += '#define mc_mctiny_BLOCKS (mc_mctiny_ROWBLOCKS * mc_mctiny_COLBLOCKS)\n'
hfile += '#define mc_mctiny_COOKIE1BLOCKBYTES %d\n' % cookie1blockbytes
hfile += '#define mc_mctiny_COOKIE2BLOCKBYTES %d\n' % cookie2blockbytes
hfile += '#define mc_mctiny_COOKIE3BLOCKBYTES %d\n' % cookie3blockbytes
hfile += '#define mc_mctiny_COOKIE9BYTES %d\n' % cookie9bytes
hfile += '\n'
hfile += '/* pktree: */\n'
hfile += '#define mc_pktree_L1BLOCKBYTES %d\n' % (l1blockbytes)
hfile += '#define mc_pktree_L2BLOCKBYTES %d\n' % (l2blockbytes)
hfile += '#define mc_pktree_L2BLOCKS %d\n' % (l2blocks)
hfile += '#define mc_pktree_L3BLOCKBYTES %d\n' % (l3blockbytes)
hfile += '#define mc_pktree_L3BLOCKS %d\n' % (l3blocks)
hfile += '#define mc_pktree_L4BLOCKBYTES mc_mctiny_BLOCKBYTES\n'
hfile += '#define mc_pktree_L4BLOCKS (mc_mctiny_ROWBLOCKS * mc_mctiny_COLBLOCKS)\n'
hfile += '\n'
hfile += '#define mc_mctiny_QUERYK0BYTES %d\n' % (queryK0bytes)
hfile += '#define mc_mctiny_REPLYK0BYTES %d\n' % (replyK0bytes)
hfile += '#define mc_mctiny_QUERYK1BYTES %d\n' % (queryK1bytes)
hfile += '#define mc_mctiny_REPLYK1BYTES %d\n' % (replyK1bytes)
hfile += '#define mc_mctiny_QUERYK2BYTES %d\n' % (queryK2bytes)
hfile += '#define mc_mctiny_REPLYK2BYTES %d\n' % (replyK2bytes)
hfile += '#define mc_mctiny_QUERYK3BYTES %d\n' % (queryK3bytes)
hfile += '#define mc_mctiny_REPLYK3BYTES %d\n' % (replyK3bytes)
hfile += '#define mc_mctiny_QUERYK4BYTES %d\n' % (queryK4bytes)
hfile += '#define mc_mctiny_REPLYK4BYTES %d\n' % (replyK4bytes)
hfile += '\n'
hfile += '#define mc_pktree_QUERYLBYTES %d\n' % (queryLbytes)
hfile += '\n'
hfile += 'struct mc_pktree {\n'
hfile += '    unsigned char l4[mc_pktree_L4BLOCKS][mc_pktree_L4BLOCKBYTES];\n'
hfile += '    unsigned char l3[mc_pktree_L3BLOCKS][mc_pktree_L3BLOCKBYTES];\n'
hfile += '    unsigned char l2[mc_pktree_L2BLOCKS][mc_pktree_L2BLOCKBYTES];\n'
hfile += '    unsigned char l1[mc_pktree_L1BLOCKBYTES];\n'
hfile += '    unsigned char l0[mc_HASHBYTES];\n'
hfile += '};\n'
hfile += '\n'
hfile += '/* mc_mctiny.c */\n'
hfile += 'extern int mc_mctiny_seedisvalid(const unsigned char *);\n'
hfile += 'extern void mc_mctiny_pk2block(unsigned char *, const unsigned char *,\n'
hfile += '                               long long, long long);\n'
hfile += 'extern void mc_mctiny_seed2e(unsigned char *, const unsigned char *);\n'
hfile += 'extern void mc_mctiny_eblock2syndrome(unsigned char *s, const unsigned char *e,\n'
hfile += '                                      const unsigned char *, long long);\n'
hfile += 'extern void mc_mctiny_pieceinit(unsigned char *, const unsigned char *,\n'
hfile += '                                long long);\n'
hfile += 'extern void mc_mctiny_pieceabsorb(unsigned char *, const unsigned char *,\n'
hfile += '                                  long long);\n'
hfile += 'extern void mc_mctiny_finalize(unsigned char *, unsigned char *,\n'
hfile += '                               const unsigned char *, const unsigned char *);\n'
hfile += 'extern void\n'
hfile += 'mc_mctiny_mergepieces(unsigned char *,\n'
hfile += '                      unsigned char[mc_mctiny_PIECES][mc_mctiny_PIECEBYTES]);\n'
hfile += '\n'
hfile += '/* mc_pktree.c */\n'
hfile += 'extern void mc_pktree_pk2tree(struct mc_pktree *, const unsigned char *);\n'
hfile += 'extern int mc_pktree_block_put(struct mc_pktree *, long long, long long,\n'
hfile += '                               unsigned char *, long long);\n'
hfile += 'extern long long mc_pktree_block_get(struct mc_pktree *, unsigned char *,\n'
hfile += '                                     long long, long long);\n'
hfile += 'extern void mc_pktree_to_pk(struct mc_pktree *, unsigned char *);\n'
hfile += '\n'
hfile += '/* mc_levpos.c */\n'
hfile += 'extern void mc_Levpos_load(long long *, long long *, int *,\n'
hfile += '                           const unsigned char *);\n'
hfile += 'extern void mc_Levpos_store(unsigned char *, long long, long long, int);\n'
hfile += '\n'
hfile += '/* mc_keys.c */\n'
hfile += 'extern int mc_keys_loadpk(unsigned char *, const unsigned char *);\n'
hfile += 'extern void mc_keys_dec(unsigned char *, const unsigned char *,\n'
hfile += '                        const unsigned char *);\n'
hfile += '/* mc_derivekeys.c */\n'
hfile += 'extern void mc_derivekeys(unsigned char *, unsigned char *,\n'
hfile += '                          const unsigned char *);\n'
hfile += '\n'
hfile += '#endif\n'

with open('mc.h', 'w') as f:
    f.write(hfile)


mdfile = f"""# KEY EXCHANGE

Key exchange - transfers two mceliece{n}{t} public keys in parallel.
One key is one-time ephemeral key and second is authorization key.

## PHASE 0

### QUERY0 - {queryK0bytes}-bytes

<table><thead>
  <tr>
    <th colspan="3">HEADER</th>
    <th colspan="2">ENCRYPTED DATA</th>
    <th colspan="2">PLAINTEXT DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>NONCE</td>
    <td>AUTH.</td>
    <td>BOX</td>
    <td>PKHASH</td>
    <td>CIPHERTEXT</td>
  </tr>
  <tr>
    <td>{magicbytes}B</td>
    <td>{extensionbytes}B</td>
    <td>{noncebytes}B</td>
    <td>{authbytes}B</td>
    <td>512B</td>
    <td>{hashbytes}B</td>
    <td>{colbytes}B</td>
  </tr>
</tbody>
</table>

- BOX - encrypted (curently empty) box
- PKHASH - server's public key hash
- CIPHERTEXT - mceliece{n}{t} ciphertext


### REPLY0 - {replyK0bytes}-bytes

<table><thead>
  <tr>
    <th colspan="3">HEADER</th>
    <th colspan="3">ENCRYPTED DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>NONCE</td>
    <td>AUTH.</td>
    <td>KEY1234QUERY</td>
    <td>KEY1234REPLY</td>
  </tr>
  <tr>
    <td>{magicbytes}B</td>
    <td>{extensionbytes}B</td>
    <td>{noncebytes}B</td>
    <td>{authbytes}B</td>
    <td>{keybytes}B</td>
    <td>{keybytes}B</td>
  </tr>
</tbody>
</table>

- KEY1234QUERY - server-generated client's encryption key for next phases 1/2/3/4
- KEY1234REPLY - server-generated server's encryption key for next phases 1/2/3/4

## PHASE 1

### QUERY1 - {queryK1bytes}-bytes, 2*{colblocks*rowblocks} packets

 <table><thead>
  <tr>
    <th colspan="3">HEADER</th>
    <th colspan="2">ENCRYPTED DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>NONCE</td>
    <td>AUTH.</td>
    <td>PUBLIC-KEY BLOCK</td>
  </tr>
  <tr>
    <td>{magicbytes}B</td>
    <td>{extensionbytes}B</td>
    <td>{noncebytes}B</td>
    <td>{authbytes}B</td>
    <td>{blockbytes}B</td>
  </tr>
</tbody>
</table>

- PUBLIC-KEY BLOCK - mctiny block

### REPLY1 - {replyK1bytes}-bytes, 2*{colblocks*rowblocks} packets

<table><thead>
  <tr>
    <th colspan="3">HEADER</th>
    <th colspan="2">ENCRYPTED DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>NONCE</td>
    <td>AUTH.</td>
    <td>COOKIE1</td>
  </tr>
  <tr>
    <td>{magicbytes}B</td>
    <td>{extensionbytes}B</td>
    <td>{noncebytes}B</td>
    <td>{authbytes}B</td>
    <td>{cookie1blockbytes}B</td>
  </tr>
</tbody>
</table>

- COOKIE1 - holds server-encrypted one piece of syndrome + 32bytes Merkle tree L3 hash of the public key block

## PHASE 2

### QUERY2 - {queryK2bytes}-bytes, 2*{pieces} packets

<table><thead>
  <tr>
    <th colspan="3">HEADER</th>
    <th colspan="5">ENCRYPTED DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>NONCE</td>
    <td>AUTH</td>
    <td>COOKIE1/0</td>
    <td>COOKIE1/1</td>
    <td rowspan="2">...</td>
    <td>COOKIE1/{colblocks*v}</td>
  </tr>
  <tr>
    <td>{magicbytes}B</td>
    <td>{extensionbytes}B</td>
    <td>{noncebytes}B</td>
    <td>{authbytes}B</td>
    <td>{cookie1blockbytes}B</td>
    <td>{cookie1blockbytes}B</td>
    <td>{cookie1blockbytes}B</td>
  </tr>
</tbody>
</table>

### REPLY2 - {replyK2bytes}-bytes, 2*{pieces} packets

<table><thead>
  <tr>
    <th colspan="3">HEADER</th>
    <th colspan="2">ENCRYPTED DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>NONCE</td>
    <td>AUTH.</td>
    <td>COOKIE2</td>
  </tr>
  <tr>
    <td>{magicbytes}B</td>
    <td>{extensionbytes}B</td>
    <td>{noncebytes}B</td>
    <td>{authbytes}B</td>
    <td>{cookie2blockbytes}B</td>
  </tr>
</tbody>
</table>

- COOKIE2 - holds server-encrypted one part of ciphertext + 32bytes Merkle tree L2 hash of L3 hashes

## PHASE 3

### QUERY3 - {queryK3bytes}-bytes, 2*{p3pieces} packets

<table><thead>
  <tr>
    <th colspan="3">HEADER</th>
    <th colspan="5">ENCRYPTED DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>NONCE</td>
    <td>AUTH</td>
    <td>COOKIE2/0</td>
    <td>COOKIE2/1</td>
    <td rowspan="2">...</td>
    <td>COOKIE2/{p3blocks}</td>
  </tr>
  <tr>
    <td>{magicbytes}B</td>
    <td>{extensionbytes}B</td>
    <td>{noncebytes}B</td>
    <td>{authbytes}B</td>
    <td>{cookie2blockbytes}B</td>
    <td>{cookie2blockbytes}B</td>
    <td>{cookie2blockbytes}B</td>
  </tr>
</tbody>
</table>

### REPLY3 - {replyK3bytes}-bytes, 2*{p3pieces} packets

<table><thead>
  <tr>
    <th colspan="3">HEADER</th>
    <th colspan="2">ENCRYPTED DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>NONCE</td>
    <td>AUTH.</td>
    <td>COOKIE3</td>
  </tr>
  <tr>
    <td>{magicbytes}B</td>
    <td>{extensionbytes}B</td>
    <td>{noncebytes}B</td>
    <td>{authbytes}B</td>
    <td>{cookie3blockbytes}B</td>
  </tr>
</tbody>
</table>

- COOKIE3 - holds server-encrypted 1/{p3pieces} of ciphertext + 32bytes Merkle tree L1 hash of L2 hashes

## PHASE 4

### QUERY4 - {queryK4bytes}-bytes, 1 packet

<table><thead>
  <tr>
    <th colspan="3">HEADER</th>
    <th colspan="5">ENCRYPTED DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>NONCE</td>
    <td>AUTH.</td>
    <td>COOKIE3/0</td>
    <td>COOKIE3/1</td>
    <td rowspan="2">...</td>
    <td>COOKIE3/{2*p3pieces}</td>
  </tr>
  <tr>
    <td>{magicbytes}B</td>
    <td>{extensionbytes}B</td>
    <td>{noncebytes}B</td>
    <td>{authbytes}B</td>
    <td>{cookie3blockbytes}B</td>
    <td>{cookie3blockbytes}B</td>
    <td>{cookie3blockbytes}B</td>
  </tr>
</tbody>
</table>

### REPLY4 - {replyK4bytes}-bytes, 1 packet

<table><thead>
  <tr>
    <th colspan="3">HEADER</th>
    <th colspan="5">ENCRYPTED DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>NONCE</td>
    <td>AUTH.</td>
    <td>ONE-TIME CIPHERTEXT</td>
    <td>AUTH. CIPHERTEXT</td>
    <td>COOKIE9</td>
  </tr>
  <tr>
    <td>{magicbytes}B</td>
    <td>{extensionbytes}B</td>
    <td>{noncebytes}B</td>
    <td>{authbytes}B</td>
    <td>{ciphertextbytes}B</td>
    <td>{ciphertextbytes}B</td>
    <td>{cookie9bytes}B</td>
  </tr>
</tbody>
</table>

- ONE-TIME CIPHERTEXT - ephemeral/one-time mceliece{n}{t} ciphertext
- AUTH. CIPHERTEXT - authorization mceliece{n}{t} ciphertext
- COOKIE9 - holds server-encrypted 32B symetric key and 32B client's authorization public-key hash

"""

with open('protocol.md', 'w') as f:
    f.write(mdfile)
