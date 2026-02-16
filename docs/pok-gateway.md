## `pok-gateway`

Run a UDP forwarding gateway used for:

- allowing a `pok-server` behind NAT to become reachable, and
- relaying client traffic to a server based on routing information in the
  32-byte packet `extension` field.

The gateway maintains a routing table mapping `serverID` (server public-key
hash) to an active registered server connection.

### Synopsis

`pok-gateway [-vqQ] -k keydir IP PORT`

### Arguments

- **`IP`**: Local IP address to bind to.
- **`PORT`**: Local UDP port to bind to.

### Options

- **`-k keydir`** (required): Change directory to `keydir` before serving.
- **`-v`**: Increase log verbosity. Can be repeated.
- **`-q`**: Set log level to USAGE.
- **`-Q`**: Set log level to FATAL.

### Forwarding behavior (high level)

- **Server registration traffic**: packets with an all-zero `extension` are
  handled as gateway server-side handshake/keepalive.
- **Forward-by-serverID**: for client traffic, the gateway uses the packet
  `extension` as a lookup key (serverID) and forwards to the registered server.
- **Forward-by-IP**: if the extension encodes an IP:port destination, the
  gateway forwards based on that destination.

See `docs/topologies.md` for diagrams, `docs/gateway-forwarding.md` for a
detailed forwarding model and NAT scenarios, and `README.md` for DNS setup
examples.

### Example

Run a gateway:

```bash
./pok-gateway -vk gatewaykeydir 0.0.0.0 11223
```

### Exit status

- **`0`**: Success.
- **`100`**: Usage error.
- **`111`**: Failure.

