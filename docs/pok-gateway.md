### NAME

pok-gateway - forward encrypted and authenticated UDP packets to a pok-server

### SYNOPSIS

`pok-gateway [-vqQ] -k keydir IP PORT`

### DESCRIPTION

**pok-gateway** forwards UDP packets to backend servers based on
routing metadata contained in the packet header.
The gateway does not decrypt or interpret application payloads.
It only parses the required unencrypted metadata to determine
the destination address and forwards packets transparently.

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

`-k` *keydir*
:   Server key directory (required). The directory contains server encryption
    keys.

*IP*
:   Local IP address to bind to.

*PORT*
:   Local UDP port to bind to.

### PACKET OVERVIEW

| Metadata | Encrypted payload |
|:--------:|:-----------------:|
| 64B      | 0-1168 B          |

### EXAMPLES

Run a gateway:

```bash
# create gateway keypair
./pok-makekey gatewaykeydir

# run gateway
./pok-gateway -k gatewaykeydir 0.0.0.0 1234
```

### SEE ALSO

pok-client(1), pok-server(1), pok-makekey(1)
