# PHASE L — PUBLIC KEY DOWNLOAD

Downloads server's long-term mceliece6688128 public key using Merkle tree distribution.
Client knows the root hash (L0) from DNS record or `-R` flag and verifies each block against its parent.

## QUERYL - 1232-bytes (all levels)

<table><thead>
  <tr>
    <th colspan="3">HEADER</th>
    <th colspan="2">PLAINTEXT DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>LEVPOS</td>
    <td>PKHASH</td>
    <td>PADDING</td>
  </tr>
  <tr>
    <td>8B</td>
    <td>32B</td>
    <td>2B</td>
    <td>32B</td>
    <td>1158B</td>
  </tr>
</tbody>
</table>

- LEVPOS - 2 bytes encoding `level` (bits 13-15), `pos` (bits 0-11)
- PKHASH - root hash of the Merkle tree (L0)

## REPLYL variants (by level)

### REPLYL1 - 138-bytes, 1 block

<table><thead>
  <tr>
    <th colspan="3">HEADER</th>
    <th colspan="1">PLAINTEXT DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>LEVPOS</td>
    <td>L1 BLOCK</td>
  </tr>
  <tr>
    <td>8B</td>
    <td>32B</td>
    <td>2B</td>
    <td>96B</td>
  </tr>
</tbody>
</table>

- L1 BLOCK - concatenation of 3 L2 block hashes

### REPLYL2 - 554-bytes, 3 blocks

<table><thead>
  <tr>
    <th colspan="3">HEADER</th>
    <th colspan="1">PLAINTEXT DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>LEVPOS</td>
    <td>L2 BLOCK</td>
  </tr>
  <tr>
    <td>8B</td>
    <td>32B</td>
    <td>2B</td>
    <td>512B</td>
  </tr>
</tbody>
</table>

- L2 BLOCK - concatenation of L3 block hashes

### REPLYL3 - 682-bytes, 47 blocks

<table><thead>
  <tr>
    <th colspan="3">HEADER</th>
    <th colspan="1">PLAINTEXT DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>LEVPOS</td>
    <td>L3 BLOCK</td>
  </tr>
  <tr>
    <td>8B</td>
    <td>32B</td>
    <td>2B</td>
    <td>640B</td>
  </tr>
</tbody>
</table>

- L3 BLOCK - concatenation of L4 block hashes

### REPLYL4 - 1176-bytes, 930 blocks

<table><thead>
  <tr>
    <th colspan="3">HEADER</th>
    <th colspan="1">PLAINTEXT DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>LEVPOS</td>
    <td>L4 BLOCK (mctiny block)</td>
  </tr>
  <tr>
    <td>8B</td>
    <td>32B</td>
    <td>2B</td>
    <td>1134B</td>
  </tr>
</tbody>
</table>

- L4 BLOCK - actual public key block (mctiny block)

# PHASE K — KEY EXCHANGE

Key exchange - transfers two mceliece6688128 public keys in parallel.
One key is one-time ephemeral key and second is authorization key.

## PHASE 0

### QUERY0 - 832-bytes

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
    <td>8B</td>
    <td>32B</td>
    <td>24B</td>
    <td>16B</td>
    <td>512B</td>
    <td>32B</td>
    <td>208B</td>
  </tr>
</tbody>
</table>

- BOX - encrypted (curently empty) box
- PKHASH - server's public key hash
- CIPHERTEXT - mceliece6688128 ciphertext


### REPLY0 - 144-bytes

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
    <td>8B</td>
    <td>32B</td>
    <td>24B</td>
    <td>16B</td>
    <td>32B</td>
    <td>32B</td>
  </tr>
</tbody>
</table>

- KEY1234QUERY - server-generated client's encryption key for next phases 1/2/3/4
- KEY1234REPLY - server-generated server's encryption key for next phases 1/2/3/4

## PHASE 1

### QUERY1 - 1214-bytes, 2*930 packets

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
    <td>8B</td>
    <td>32B</td>
    <td>24B</td>
    <td>16B</td>
    <td>1134B</td>
  </tr>
</tbody>
</table>

- PUBLIC-KEY BLOCK - mctiny block

### REPLY1 - 131-bytes, 2*930 packets

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
    <td>8B</td>
    <td>32B</td>
    <td>24B</td>
    <td>16B</td>
    <td>51B</td>
  </tr>
</tbody>
</table>

- COOKIE1 - holds server-encrypted one piece of syndrome + 32bytes Merkle tree L3 hash of the public key block

## PHASE 2

### QUERY2 - 1100-bytes, 2*47 packets

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
    <td>COOKIE1/20</td>
  </tr>
  <tr>
    <td>8B</td>
    <td>32B</td>
    <td>24B</td>
    <td>16B</td>
    <td>51B</td>
    <td>51B</td>
    <td>51B</td>
  </tr>
</tbody>
</table>

### REPLY2 - 133-bytes, 2*47 packets

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
    <td>8B</td>
    <td>32B</td>
    <td>24B</td>
    <td>16B</td>
    <td>53B</td>
  </tr>
</tbody>
</table>

- COOKIE2 - holds server-encrypted one part of ciphertext + 32bytes Merkle tree L2 hash of L3 hashes

## PHASE 3

### QUERY3 - 928-bytes, 2*3 packets

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
    <td>COOKIE2/16</td>
  </tr>
  <tr>
    <td>8B</td>
    <td>32B</td>
    <td>24B</td>
    <td>16B</td>
    <td>53B</td>
    <td>53B</td>
    <td>53B</td>
  </tr>
</tbody>
</table>

### REPLY3 - 208-bytes, 2*3 packets

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
    <td>8B</td>
    <td>32B</td>
    <td>24B</td>
    <td>16B</td>
    <td>128B</td>
  </tr>
</tbody>
</table>

- COOKIE3 - holds server-encrypted 1/3 of ciphertext + 32bytes Merkle tree L1 hash of L2 hashes

## PHASE 4

### QUERY4 - 848-bytes, 1 packet

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
    <td>COOKIE3/6</td>
  </tr>
  <tr>
    <td>8B</td>
    <td>32B</td>
    <td>24B</td>
    <td>16B</td>
    <td>128B</td>
    <td>128B</td>
    <td>128B</td>
  </tr>
</tbody>
</table>

### REPLY4 - 640-bytes, 1 packet

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
    <td>8B</td>
    <td>32B</td>
    <td>24B</td>
    <td>16B</td>
    <td>208B</td>
    <td>208B</td>
    <td>144B</td>
  </tr>
</tbody>
</table>

- ONE-TIME CIPHERTEXT - ephemeral/one-time mceliece6688128 ciphertext
- AUTH. CIPHERTEXT - authorization mceliece6688128 ciphertext
- COOKIE9 - holds server-encrypted 32B symetric key and 32B client's authorization public-key hash

# PHASE I — INITIALIZATION

Finalize session establishment after key exchange. Client sends `cookie9` to server, both sides derive final session keys and initialize keyratchet for message transport.

## QUERYI - 232-bytes

<table><thead>
  <tr>
    <th colspan="3">HEADER</th>
    <th colspan="2">ENCRYPTED DATA</th>
    <th colspan="1">PLAINTEXT DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>NONCE</td>
    <td>AUTH.</td>
    <td>CLIENTTM</td>
    <td>COOKIE9</td>
  </tr>
  <tr>
    <td>8B</td>
    <td>32B</td>
    <td>24B</td>
    <td>16B</td>
    <td>8B</td>
    <td>144B</td>
  </tr>
</tbody>
</table>

- NONCE - must be `id(16B) || 0x00(8B)` (last 8 bytes zero)
- CLIENTTM - client timestamp (encrypted)
- COOKIE9 - obtained from REPLY4 (plaintext, not encrypted by init key)

## REPLYI - 88-bytes

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
    <td>SERVERTM</td>
  </tr>
  <tr>
    <td>8B</td>
    <td>32B</td>
    <td>24B</td>
    <td>16B</td>
    <td>8B</td>
  </tr>
</tbody>
</table>

- SERVERTM - server timestamp (encrypted)

After this phase both sides derive final 3×32B session key material via `shake256(key9, 2×32B)` and initialize `keyratchet_enc` and `keyratchet_dec` for M/P phases.

# PHASE M — MESSAGE TRANSPORT

Application data transport using keyratchet encryption. Messages are framed and encrypted, with up to 1152 bytes of encrypted payload per packet.

## QUERYM - 1232-bytes (max)

<table><thead>
  <tr>
    <th colspan="4">HEADER</th>
    <th colspan="2">ENCRYPTED DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>ID</td>
    <td>NONCE</td>
    <td>AUTH.</td>
    <td>MESSAGE</td>
  </tr>
  <tr>
    <td>8B</td>
    <td>32B</td>
    <td>16B</td>
    <td>8B</td>
    <td>16B</td>
    <td>0-1152B</td>
  </tr>
</tbody>
</table>

- ID - session identifier (16 bytes)
- NONCE - 8-byte keyratchet nonce (counter + epoch)
- AUTH. - 16-byte authenticator
- MESSAGE - encrypted message payload

Message payload uses internal framing (32-byte header + up to 1120-byte data block) for acknowledgments, EOF signaling, and reliable ordered delivery.

## REPLYM - 1232-bytes (max)

<table><thead>
  <tr>
    <th colspan="4">HEADER</th>
    <th colspan="2">ENCRYPTED DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>ID</td>
    <td>NONCE</td>
    <td>AUTH.</td>
    <td>MESSAGE</td>
  </tr>
  <tr>
    <td>8B</td>
    <td>32B</td>
    <td>16B</td>
    <td>8B</td>
    <td>16B</td>
    <td>0-1152B</td>
  </tr>
</tbody>
</table>

- ID - session identifier (16 bytes)
- NONCE - 8-byte keyratchet nonce (counter + epoch)
- AUTH. - 16-byte authenticator
- MESSAGE - encrypted message payload

# PHASE P — PING / KEEPALIVE

Keepalive packets with no application payload. Uses same keyratchet as PHASE M.

## QUERYP - 80-bytes

<table><thead>
  <tr>
    <th colspan="4">HEADER</th>
    <th colspan="1">ENCRYPTED DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>ID</td>
    <td>NONCE</td>
    <td>AUTH.</td>
  </tr>
  <tr>
    <td>8B</td>
    <td>32B</td>
    <td>16B</td>
    <td>8B</td>
    <td>16B</td>
  </tr>
</tbody>
</table>

- ID - session identifier (16 bytes)
- NONCE - 8-byte keyratchet nonce (counter + epoch)
- AUTH. - 16-byte authenticator for 0-byte encrypted payload

## REPLYP - 80-bytes

<table><thead>
  <tr>
    <th colspan="4">HEADER</th>
    <th colspan="1">ENCRYPTED DATA</th>
  </tr></thead>
<tbody>
  <tr>
    <td>MAGIC</td>
    <td>EXTENSION</td>
    <td>ID</td>
    <td>NONCE</td>
    <td>AUTH.</td>
  </tr>
  <tr>
    <td>8B</td>
    <td>32B</td>
    <td>16B</td>
    <td>8B</td>
    <td>16B</td>
  </tr>
</tbody>
</table>

- ID - session identifier (16 bytes)
- NONCE - 8-byte keyratchet nonce
- AUTH. - 16-byte authenticator for 0-byte encrypted payload

