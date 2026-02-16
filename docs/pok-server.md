### NAME

pok-server - accept encrypted and authenticated UDP sessions from pok-client

### SYNOPSIS

`pok-server [-vqQcCgr] [-R gatewayID] [-w pattern] [-T seconds] [-t seconds] -k keydir [-G host:port] IP PORT prog`

### DESCRIPTION

**pok-server** is a utility that, together with **pok-client**,
creates an encrypted and authenticated communication channel
between a remote program (started using **pok-client**)
and a local program *prog*.

**pok-server** is the server-side component of this pair. It receives
encrypted and authenticated UDP packets from **pok-client**, verifies
and decrypts them, and forwards the resulting data to the local
program *prog*.

**POK** is an acronym for Postquantum OverKill. The name reflects
the use of conservative, high-security cryptographic choices,
notably the large ("overkill") Classic McEliece parameter set
mceliece6688128.

### OPTIONS

`-q`
:   Quiet mode. Suppress error messages.

`-Q`
:   Normal mode (default).

`-v`
:   Enable verbose mode. Multiple -v options increase the verbosity.

`-c`
:   Enable colored log output.

`-C`
:   Disable colored log output.

`-w` *pattern*
:   Add a log whitelist pattern.

`-T` *seconds*
:   Gateway key-exchange timeout. Range: 1–3600. Default: `120`.

`-t` *seconds*
:   Session timeout. Range: 1–3600. Default: `300`. When gateway mode is
    enabled, this value is also used as the gateway keepalive timeout
    threshold.

`-G` *host:port*
:   Enable gateway mode and set the gateway address. The server will
    resolve the gateway host to IP candidates and determine the gateway
    public-key hash (gatewayID) from a DNS TXT record (unless overridden with
    `-R`).

`-g`
:   Disable gateway mode (default).

`-R` *hex-string*
:   Do not resolve gatewayID from a TXT record. Use the value from `-R`
    *hex-string*.

`-r`
:   Resolve gatewayID from a DNS TXT record (default).

`-k` *keydir*
:   Server key directory (required). The directory contains server encryption
    keys.

*IP*
:   Local IP address to bind to.

*PORT*
:   Local UDP port to bind to.

*prog*
:   Program executed for each connection.

### SIGNALS

`SIGTERM`
:   Request a clean shutdown.

`SIGUSR1`
:   Increase log verbosity.

`SIGUSR2`
:   Decrease log verbosity.

### EXAMPLES

Simple hello-world example:

```bash
# create server keypair
./pok-makekey serverkeydir
pok-makekey: info: mceliece6688128 public-key created 'serverkeydir/public/<serverID>'
pok-makekey: info: mceliece6688128 secret-key created 'serverkeydir/secret/<serverID>'

# run server
./pok-server -k serverkeydir 127.0.0.1 1234 sh -c 'echo "HELLO WORLD"'

# run client (replace <serverID>)
./pok-client -R <serverID> 127.0.0.1 1234 sh -c 'cat >&2'
```

### SEE ALSO

pok-client(1), pok-gateway(1), pok-makekey(1)
