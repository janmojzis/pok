## `pok-client`

Establish an encrypted and authenticated UDP session to a `pok-server`
directly, or via a `pok-gateway` (routing is controlled by the packet
`extension` field).

The connection setup uses phases L/K/I and then transports application data
with phases M/P. See `protocol.md` for the on-wire formats.

### Synopsis

`pok-client [-vqQcCr] [-t session-timeout] [-T kex-timeout] [-R server-pk-hash] [-E extension] [-k keydir -a authorization-hash] host port [prog]`

### Arguments

- **`host`**: Server hostname or IP address to connect to.
- **`port`**: Server UDP port.
- **`prog`** (optional): Program to execute. If omitted, the message handler
  redirects input/output to `stdin`/`stdout` instead of executing a child
  program.

### Options

- **Logging**
  - **`-v`**: Increase log verbosity. Can be repeated.
  - **`-q`**: Set log level to USAGE.
  - **`-Q`**: Set log level to FATAL.
  - **`-c`**: Enable colored log output.
  - **`-C`**: Disable colored log output.
- **Timeouts**
  - **`-T seconds`**: Key-exchange timeout. Range: 1–3600. Default: `120`.
  - **`-t seconds`**: Session timeout. Range: 1–3600. Default: `300`.
- **Server public-key hash (serverID)**
  - **`-R hexhash`**: Set the server public-key hash explicitly (hex string).
  - **`-r`**: Reset `-R` and use DNS TXT lookup instead.

    If `-R` is not provided (or reset with `-r`), the client resolves the hash
    from the `host` TXT record with the `PoKv0dD=` prefix.
- **Authorization**
  - **`-k keydir`**: Change directory to `keydir` before reading keys.
  - **`-a hexhash`**: Client authorization public-key hash (hex string).
    Requires `-k`.
- **Routing / extension**
  - **`-E extension`**: Override the 32-byte packet `extension` field. If `-E`
    is not provided (or empty), the default is the server public-key hash
    (serverID), which enables gateway forwarding.

    The string format accepted by `-E` is documented in `README.md`
    ("Extension format (-E)").

### Typical usage

Direct client → server (explicit server pkhash):

```bash
./pok-client -vk clientkeydir -a <client_auth_pkhash> -R <server_pkhash> 127.0.0.1 1234
```

Gateway mode (client still targets `host`, DNS A may point to the gateway;
server pkhash comes from TXT by default):

```bash
./pok-client -vk clientkeydir -a <client_auth_pkhash> myserver.example.com 1234
```

### Exit status

- **`0`**: Success (child program exit status is propagated when `prog` is
  used).
- **`100`**: Usage error.
- **`111`**: Failure (network/parse/key exchange errors, etc.).

