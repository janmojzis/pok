# Packet flow diagrams

This file documents the high-level packet flow for:
- direct `client-server`
- relayed `client-gateway-server` (forwarder)

## Legend
- **Phases**: `L` (download PK), `K` (KEX 0..4), `I` (init), `M` (traffic), `P` (keepalive)
- **serverID**: 32B identifier carried in `extension` (recommended: `serverpkhash`, i.e., Merkle root / DNS `PoKv0dD=` value)
- In `client-gateway-server`, the gateway uses `serverID` to select the registered server, and may temporarily overwrite `extension` on forwarded packets for reply routing.

## Direct: client-server

```mermaid
sequenceDiagram
participant Client as pokClient
participant Server as pokServer

note over Client,Server: L = download server PK (Merkle blocks)
Client->>Server: QUERYL (extension=serverID, lev/pos, pkhash)
Server->>Client: REPLYL (block)

note over Client,Server: K = key exchange 0..4 (mctiny)
Client->>Server: QUERYK0 (extension=serverID, plaintext pkhash+ciphertext)
Server->>Client: REPLYK0
Client->>Server: QUERYK1..K4
Server->>Client: REPLYK1..K4

note over Client,Server: I = init (start ratchet, id=16B)
Client->>Server: QUERYI (extension=serverID, nonce=id||0..0, cookie9)
Server->>Client: REPLYI

note over Client,Server: M = traffic, P = keepalive (ratchet)
Client->>Server: QUERYM (extension=serverID, id, nonce8, enc payload)
Server->>Client: REPLYM (extension=serverID, id, nonce8, enc payload)
Client->>Server: QUERYP (extension=serverID, id, nonce8)
Server->>Client: REPLYP
```

## Relayed: client-gateway-server (forwarder)

```mermaid
sequenceDiagram
participant Client as pokClient
participant GW as pokGateway
participant Server as pokServer

note over Server,GW: Server registration: extension=0, uses authorization key
Server->>GW: QUERYL/K (extension=0)
note over GW: extension==0 → srv() → server_phaseL/K
GW->>Server: REPLYL/K
Server->>GW: QUERYI (extension=0, authKey=serverpkhash)
note over GW: server_phaseI extracts authhash (=serverID)\nAdd routing: serverID -> server_conn
GW->>Server: REPLYI

note over Server,GW: Server keepalive (extension=0)
Server->>GW: QUERYP (extension=0, id)
note over GW: extension==0 → srv()\npingclient_find(id) → serve
GW->>Server: REPLYP

note over Client,GW: Client always sends extension=serverID
note over Client,Server: Client traffic forwarding by serverID

Client->>GW: QUERYL/K/I/M/P (extension=serverID)
note over GW: extension!=0 → fwd()\nlookup serverID in routing table\nrewrite extension=clientIp:clientPort
GW->>Server: forward QUERY (extension=clientIp:clientPort)
Server->>GW: REPLY (extension=clientIp:clientPort echoed)
note over GW: swap destination using clientIp:clientPort from packet
GW->>Client: forward REPLY (extension restored)
```

### Gateway dispatch: extension-based routing

Gateway uses simple stateless dispatch based on `extension`:

1. **`extension == 0` (32B zeros)** → Gateway connection (srv)
   - Serves K/L/I/P packets as server
   - After I: extracts `authhash` (authorization PK hash) = `serverID`
   - Creates routing entry: `serverID → server_conn`

2. **`extension == serverID` (32B hash)** → Forward mode (fwd)
   - Lookup `pingclient_findpk(serverID)` → find registered server
   - Forward packet with rewritten `extension=clientIp:clientPort`

3. **`extension == IP:PORT + zeros`** → IP forwarder mode (ipfwd)
   - Legacy mode for direct IP routing

**Key cryptographic property**: Server proves ownership of `serverID` by using its authorization private key during handshake. Gateway verifies this in `server_phaseI`, ensuring only legitimate servers can register under a given `serverID`.


