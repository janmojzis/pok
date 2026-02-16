# authenticated client example

## scenario

```mermaid
flowchart LR
  clientNode["pok-client"] -->|"UDP"| serverNode["pok-server"]
```

## run hello-world server
```
# create server keypair
./pok-makekey serverkeydir
pok-makekey: info: mceliece6688128 public-key created 'serverkeydir/public/c10e557e4dc562e9b6408951815b9c9cbfd03b84bec59cd157e5ef486ebe01d1'
pok-makekey: info: mceliece6688128 secret-key created 'serverkeydir/secret/c10e557e4dc562e9b6408951815b9c9cbfd03b84bec59cd157e5ef486ebe01d1'

# run server
./pok-server -vk serverkeydir 127.0.0.1 1234 sh -c 'echo ========== HELLO WORLD ==========' &
```

## authenticated client connection
```
# run client (replace with YOUR KEYIDs)
./pok-client -vk clientkeydir -R c10e557e4dc562e9b6408951815b9c9cbfd03b84bec59cd157e5ef486ebe01d1 127.0.0.1 1234 sh -c 'cat >&2'

# create client's authentication keypair
./pok-makekey clientkeydir
pok-makekey: info: mceliece6688128 public-key created 'clientkeydir/public/6f62f419d991cea2ac79f27583cf9a80398863f5b9330432003b2f0a8ba12305'
pok-makekey: info: mceliece6688128 secret-key created 'clientkeydir/secret/6f62f419d991cea2ac79f27583cf9a80398863f5b9330432003b2f0a8ba12305'

# run client (replace with YOUR KEYIDs)
./pok-client -vk clientkeydir -R c10e557e4dc562e9b6408951815b9c9cbfd03b84bec59cd157e5ef486ebe01d1 -a 6f62f419d991cea2ac79f27583cf9a80398863f5b9330432003b2f0a8ba12305 127.0.0.1 1234 sh -c 'cat >&2'
```
