## INTRODUCTION

It is a tool that establishes an encrypted and authenticated connection between
a network client and a server. The connection is created using UDP packets,
encrypted with the `XSalsa20` algorithm, and authenticated with the `Poly1305`
algorithm. The [Classic McEliece cryptosystem](https://classic.mceliece.org)
specifically the `mceliece6688128` variant is used to exchange public keys.
All these algorithms provide sufficient long-term protection against computer
attacks, including future attacks using quantum computers.

The tool will work in the classic client-server mode, but also aims
to be used in the `client-forwarder-server` mode. Which can be used in cases
where the network structure is more complex (e.g. server behind NAT).
In particular, it aims to be able to easily set up peer-peer connections.


## Build and run tests
- needs libmceliece-dev, librandombytes-dev (apt-get install libmceliece-dev librandombytes-dev)
```
make
make test
```

## Test key-exchange
```
# create server keypair
./pok-makekey serverkeydir
pok-makekey: info: mceliece6688128 public-key created 'serverkeydir/public/c03e3750a767614ad666d803aab4a71dce6a57d45dcd61315222944de972fd20'
pok-makekey: info: mceliece6688128 secret-key created 'serverkeydir/secret/c03e3750a767614ad666d803aab4a71dce6a57d45dcd61315222944de972fd20'

# run server
./pok-server -vk serverkeydir 127.0.0.1 1234 true

# create client's authorization keypair
./pok-makekey clientkeydir
pok-makekey: info: mceliece6688128 public-key created 'clientkeydir/public/416869fcdca87deaf44461f4c22ea491190edbde21fb40931d9724529aa6d84f'
pok-makekey: info: mceliece6688128 secret-key created 'clientkeydir/secret/416869fcdca87deaf44461f4c22ea491190edbde21fb40931d9724529aa6d84f'

# run client (replace with YOUR KEYIDs)
./pok-client -vk clientkeydir -a 416869fcdca87deaf44461f4c22ea491190edbde21fb40931d9724529aa6d84f -R c03e3750a767614ad666d803aab4a71dce6a57d45dcd61315222944de972fd20 127.0.0.1 1234
```
