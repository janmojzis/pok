## `pok-makekey`

Generate a Classic McEliece `mceliece6688128` keypair and write it into a
directory structure suitable for use by the other `pok-*` binaries.

This tool creates:

- `keydir/public/<hexhash>`: the public key
- `keydir/secret/<hexhash>`: the secret key (restricted permissions)

The `<hexhash>` is derived from the Merkle tree root hash of the public key.

### Synopsis

`pok-makekey [-vqQf] keydir`

### Arguments

- **`keydir`**: Directory to create (or reuse with `-f`) for generated keys.

### Options

- **`-v`**: Increase log verbosity. Can be repeated.
- **`-q`**: Set log level to FATAL.
- **`-Q`**: Set log level to ERROR.
- **`-f`**: Force mode. Allows using an existing `keydir` directory and
  overwriting `public/` and `secret/` contents.

Notes:

- In this binary, `-q`/`-Q` meanings differ from `pok-client`/`pok-server`
  (see their docs).

### Examples

Create a new key directory:

```bash
./pok-makekey serverkeydir
```

Create (or reuse) an existing directory and increase verbosity:

```bash
./pok-makekey -vvf serverkeydir
```

### Exit status

- **`0`**: Success.
- **`100`**: Usage error.
- **`111`**: Failure (I/O errors, permission problems, etc.).

