### NAME

pok-makekey - create a directory containing mceliece6688128 encryption keys

### SYNOPSIS

`pok-makekey [-vqQf] keydir`

### DESCRIPTION

**pok-makekey** generates a Classic McEliece mceliece6688128 key pair and
writes it into a directory structure suitable for use by the pok-gateway,
pok-client, and pok-server binaries.

This tool creates:

- `keydir/public/<keyID>`: the public key
- `keydir/secret/<keyID>`: the secret key (with restricted permissions)

The `<keyID>` is the key identifier; in fact, it is the Merkle tree root
hash of the public key.

### OPTIONS

`-q`
:   Quiet mode. Suppress error messages.

`-Q`
:   Normal mode (default).

`-v`
:   Enable verbose mode. Multiple -v options increase the verbosity.

`-f`
:   Force mode. Allow adding new keys to an existing *keydir*.

*keydir*
:   Directory to create (or reuse with `-f`) for generated keys.

### EXAMPLES

Create a new key directory:

```bash
./pok-makekey serverkeydir
```

Create (or reuse) an existing directory:

```bash
./pok-makekey -f serverkeydir
```

### SEE ALSO

pok-gateway(1), pok-client(1), pok-server(1)
