# KEY EXCHANGE

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

### REPLY4 - 600-bytes, 1 packet

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
    <td>104B</td>
  </tr>
</tbody>
</table>

- ONE-TIME CIPHERTEXT - ephemeral/one-time mceliece6688128 ciphertext
- AUTH. CIPHERTEXT - authorization mceliece6688128 ciphertext
- COOKIE9 - holds server-encrypted 32B symetric key and 32B client's authorization public-key hash

