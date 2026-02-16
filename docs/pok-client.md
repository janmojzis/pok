### NAME

pok-client - establish an encrypted and authenticated UDP session to a pok-server

### SYNOPSIS

`pok-client [-vqQcCr] [-t session-timeout] [-T kex-timeout] [-R server-pk-hash] [-E extension] [-k keydir -a authorization-hash] host port [prog]`

### DESCRIPTION

**pok-client** is a utility that, together with **pok-server**,
creates an encrypted and authenticated communication channel.
**pok-client** is the client-side component of this pair.
When the secure session is established, **pok-client** sends data between the
local program *prog* and the remote program launched by **pok-server**.

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

`-T` *seconds*
:   Key-exchange timeout. Range: 1–3600. Default: `120`.

`-t` *seconds*
:   Session timeout. Range: 1–3600. Default: `300`.


`-R` *hex-string*
:   Do not resolve serverID from a TXT record. Use the value from `-R`
    *hex-string*.

`-r`
:   Resolve serverID from a DNS TXT record (default).


`-k` *keydir*
:   Change directory to *keydir* before reading keys.

`-a` *hexhash*
:   Client authorization public-key hash (hex string). Requires `-k`.

`-E` *extension*
:   Override the 32-byte packet extension field.

*host*
:   Server hostname or IP address to connect to.

*port*
:   Server UDP port.

*prog*
:   Program to execute. If omitted, the message handler redirects input/output
     to stdin/stdout instead of executing a child program.

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

pok-server(1), pok-gateway(1), pok-makekey(1)

