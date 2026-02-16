## INTRODUCTION
It is a tool that establishes an encrypted and authenticated connection between
a network client and a server. The connection is created using encrypted UDP
packets.

### GOAL1 - STRONG ENCRYPTION
Encryption is provided by algorithms that are resistant to attacks using
quantum computers.
- [Classic McEliece mceliece6688128](https://lib.mceliece.org)
- XSalsa20
- [Poly1305](https://lib1305.cr.yp.to)

### GOAL2 - universal connections
The tool works in the classic `client-server` mode, but also aims
to be used in the `client-gateway-server` mode. Which can be used in cases
where the network structure is more complex (e.g. server behind NAT).
In particular, it aims to be able to easily set up peer-peer connections.


## KEY EXCHANGE (three mceliece6688128 keys):
Before a client can create an encrypted and authenticated connection, it needs
to know the server's long-term public key. The McEliece mceliece6688128 variant
has a 1MB public key. The server’s long-term public key is split into small
packet-sized blocks. And these blocks are transferred using separate packets.
In order to verify whether a transmitted packet is unchanged, the public key
is distributed as a Merkle tree. And the root hash of the tree is stored in
DNS record. Inspiration taken from [Pqconnect](https://www.pqconnect.net/).

Then, it is necessary to transfer an ephemeral key, in our case,
a one-time public key transferred from the client to the server using
[mctiny](https://mctiny.org)-like protocol.

Third public key transferred is the authorization public key. It's transmitted
from the client to the server, just like the one-time public key using 
[mctiny](https://mctiny.org)-like protocol.


## Build and run tests
- needs libmceliece-dev, librandombytes-dev (apt-get install libmceliece-dev librandombytes-dev)
```
make
make test
```

## Test key-exchange
```
# create server keypair
./pok-makekey serverkeydir
pok-makekey: info: mceliece6688128 public-key created 'serverkeydir/public/c03e3750a767614ad666d803aab4a71dce6a57d45dcd61315222944de972fd20'
pok-makekey: info: mceliece6688128 secret-key created 'serverkeydir/secret/c03e3750a767614ad666d803aab4a71dce6a57d45dcd61315222944de972fd20'

# run server
./pok-server -vk serverkeydir 127.0.0.1 1234 true

# create client's authorization keypair
./pok-makekey clientkeydir
pok-makekey: info: mceliece6688128 public-key created 'clientkeydir/public/416869fcdca87deaf44461f4c22ea491190edbde21fb40931d9724529aa6d84f'
pok-makekey: info: mceliece6688128 secret-key created 'clientkeydir/secret/416869fcdca87deaf44461f4c22ea491190edbde21fb40931d9724529aa6d84f'

# run client (replace with YOUR KEYIDs)
./pok-client -vk clientkeydir -a 416869fcdca87deaf44461f4c22ea491190edbde21fb40931d9724529aa6d84f -R c03e3750a767614ad666d803aab4a71dce6a57d45dcd61315222944de972fd20 127.0.0.1 1234
```

## Extension format (-E)
The `-E` option allows overriding the 32-byte `extension` field with a parsed
`host[:port]` string. For IPv6 with a port, use the bracketed form
`[IPv6]:port` (brackets are only allowed for IPv6). Empty port (e.g. `host:`)
is accepted.

## Gateway forwarding mode

The `pok-gateway` component allows running a server behind NAT or creating a relay point. In this setup:
- `pok-server` registers to `pok-gateway` and maintains the connection via keepalive packets
- `pok-client` connects to the gateway (using DNS that points to gateway's IP)
- Packets are automatically forwarded based on `serverID` (server's public key hash)

### How it works

1. **Client always uses serverID**: Every packet from `pok-client` includes the target server's public key hash (`serverpkhash`) in the 32-byte `extension` field. This happens automatically - the client doesn't need to know whether it's going direct or through a gateway.

2. **Gateway routing**: `pok-gateway` maintains a routing table mapping `serverID → server_conn`. When a packet arrives:
   - If it's a registration attempt (from `pok-server`): gateway processes it as a server
   - If it's client traffic: gateway looks up the `serverID` in extension and forwards to the registered server

3. **Server registration**: `pok-server` connects to gateway as a client (using the server's existing UDP socket), with its own `serverpkhash` as the `serverID`. The registration and keepalive (`P` packets) are integrated into the server's main loop.

### DNS setup

For a server `myserver.example.com` behind gateway `gw.example.com`:

```
# Gateway DNS
gw.example.com.     A       203.0.113.10
gw.example.com.     TXT     "PoKv0dD=<gateway-pkhash>"

# Server DNS (points to gateway IP, but TXT has server's pkhash)
myserver.example.com.   A       203.0.113.10
myserver.example.com.   TXT     "PoKv0dD=<server-pkhash>"
```

## Further documentation

- `docs/pok-makekey.md`
- `docs/pok-client.md`
- `docs/pok-server.md`
- `docs/pok-gateway.md`
- `docs/topologies.md`
- `docs/gateway-forwarding.md`
