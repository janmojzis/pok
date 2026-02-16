## `pok-server`

Run a UDP server that accepts `pok-client` sessions, performs key exchange,
and then spawns per-client child processes to handle application message
transport.

The server can optionally register to a `pok-gateway` and keep that
registration alive so clients can reach the server behind NAT.

### Synopsis

`pok-server [-vqQcCgr] [-R gateway-pk-hash] [-w pattern] [-T seconds] [-t seconds] -k keydir [-G host:port] host port prog`

### Arguments

- **`host`**: Local IP address to bind to.
- **`port`**: Local UDP port to bind to.
- **`prog`**: Program executed for each client connection.
- **`-k keydir`**: Server key directory (required). The server `chdir()`s to
  this directory before reading keys.

### Options

- **Logging**
  - **`-v`**: Increase log verbosity. Can be repeated.
  - **`-q`**: Set log level to USAGE.
  - **`-Q`**: Set log level to FATAL.
  - **`-c`**: Enable colored log output.
  - **`-C`**: Disable colored log output.
  - **`-w pattern`**: Add a log whitelist pattern.
- **Timeouts**
  - **`-T seconds`**: Gateway key-exchange timeout. Range: 1–3600.
    Default: `120`.
  - **`-t seconds`**: Session timeout. Range: 1–3600. Default: `300`.

    When gateway mode is enabled, this value is also used as the gateway
    keepalive timeout threshold.
- **Gateway mode**
  - **`-G host:port`**: Enable gateway mode and set the gateway address.
    The server will resolve the gateway host to IP candidates and determine the
    gateway public-key hash via DNS TXT (unless overridden with `-R`).
  - **`-R hexhash`**: Set the gateway public-key hash explicitly (hex string).
  - **`-r`**: Reset `-R` and use DNS TXT lookup instead.
  - **`-g`**: Disable gateway mode (reset any previously provided `-G`).

### Typical usage

Direct server:

```bash
./pok-server -vk serverkeydir 127.0.0.1 1234 true
```

Server registering to a gateway:

```bash
./pok-server -vk -G gw.example.com:11223 serverkeydir 0.0.0.0 1234 /usr/bin/myservice
```

### Notes

- Gateway authorization is the server public-key hash (serverID). When gateway
  mode is enabled, the server determines its public-key hash from the `public/`
  directory and uses it to authenticate to the gateway.
- Wire formats and phases L/K/I/M/P are specified in `protocol.md`.

### Exit status

- **`0`**: Success.
- **`100`**: Usage error.
- **`111`**: Failure (bind errors, key exchange errors, gateway timeout, etc.).

