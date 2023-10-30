CC?=cc
CFLAGS+=-W -Wall -Os -fPIC -fwrapv -pedantic -DSOCKET_QUEUE=1 -Icryptoint
LDFLAGS+=-lmceliece -lrandombytes -lresolv

BINARIES=pok-client
BINARIES+=pok-makekey
BINARIES+=pok-server

all: $(BINARIES)

blocking.o: blocking.c blocking.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c blocking.c

byte.o: byte.c cryptoint/crypto_int16.h byte.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c byte.c

client_downloadpk.o: client_downloadpk.c pacing.h mc.h socket.h seconds.h \
 e.h log.h byte.h packet.h client.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_downloadpk.c

client_kex.o: client_kex.c pacing.h mc.h socket.h seconds.h e.h log.h \
 byte.h packet.h client_kex.h client.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_kex.c

client_kex_query0.o: client_kex_query0.c byte.h log.h client_kex.h mc.h \
 socket.h packet.h pacing.h client.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_kex_query0.c

client_kex_query1.o: client_kex_query1.c byte.h log.h client_kex.h mc.h \
 socket.h packet.h pacing.h client.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_kex_query1.c

client_kex_query2.o: client_kex_query2.c byte.h packet.h client.h mc.h \
 client_kex.h socket.h pacing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_kex_query2.c

client_kex_query3.o: client_kex_query3.c byte.h packet.h client.h mc.h \
 client_kex.h socket.h pacing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_kex_query3.c

client_kex_query4.o: client_kex_query4.c byte.h packet.h client.h mc.h \
 client_kex.h socket.h pacing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_kex_query4.c

client_kex_reply0.o: client_kex_reply0.c log.h byte.h packet.h \
 client_kex.h mc.h socket.h pacing.h client.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_kex_reply0.c

client_kex_reply1.o: client_kex_reply1.c log.h byte.h packet.h \
 client_kex.h mc.h socket.h pacing.h client.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_kex_reply1.c

client_kex_reply2.o: client_kex_reply2.c log.h byte.h packet.h \
 client_kex.h mc.h socket.h pacing.h client.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_kex_reply2.c

client_kex_reply3.o: client_kex_reply3.c log.h byte.h packet.h \
 client_kex.h mc.h socket.h pacing.h client.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_kex_reply3.c

client_kex_reply4.o: client_kex_reply4.c log.h byte.h packet.h \
 client_kex.h mc.h socket.h pacing.h client.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_kex_reply4.c

client_recv.o: client_recv.c mc.h log.h byte.h socket.h client.h packet.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_recv.c

client_send.o: client_send.c mc.h log.h socket.h client.h packet.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_send.c

crypto_block.o: crypto_block.c crypto_block.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_block.c

crypto_onetimeauth_poly1305.o: crypto_onetimeauth_poly1305.c \
 cryptoint/crypto_int16.h cryptoint/crypto_uint32.h \
 cryptoint/crypto_uint64.h crypto_onetimeauth_poly1305.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_onetimeauth_poly1305.c

crypto_stream_xsalsa20.o: crypto_stream_xsalsa20.c \
 crypto_stream_xsalsa20.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_stream_xsalsa20.c

e.o: e.c e.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c e.c

int16_optblocker.o: int16_optblocker.c cryptoint/crypto_int16.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c int16_optblocker.c

int32_optblocker.o: int32_optblocker.c cryptoint/crypto_int32.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c int32_optblocker.c

int64_optblocker.o: int64_optblocker.c cryptoint/crypto_int64.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c int64_optblocker.c

int8_optblocker.o: int8_optblocker.c cryptoint/crypto_int8.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c int8_optblocker.c

log.o: log.c e.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c log.c

mc_derivekeys.o: mc_derivekeys.c crypto_stream_xsalsa20.h byte.h mc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c mc_derivekeys.c

mc_keys.o: mc_keys.c mc.h byte.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c mc_keys.c

mc_levpos.o: mc_levpos.c uint16_unpack.h uint16_pack.h mc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c mc_levpos.c

mc_mctiny.o: mc_mctiny.c mc.h log.h crypto_stream_xsalsa20.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c mc_mctiny.c

mc_pktree.o: mc_pktree.c byte.h log.h seconds.h mc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c mc_pktree.c

nk.o: nk.c crypto_stream_xsalsa20.h crypto_block.h uint64_pack.h byte.h \
 packet.h nk.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c nk.c

open_cwd.o: open_cwd.c open.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c open_cwd.c

open_pipe.o: open_pipe.c open.h blocking.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c open_pipe.c

open_read.o: open_read.c open.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c open_read.c

open_write.o: open_write.c open.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c open_write.c

pacing.o: pacing.c pacing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c pacing.c

packet.o: packet.c packet.h crypto_stream_xsalsa20.h \
 crypto_onetimeauth_poly1305.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c packet.c

parsehex.o: parsehex.c e.h parsehex.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c parsehex.c

parseip.o: parseip.c e.h log.h parseip.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c parseip.c

parsenum.o: parsenum.c e.h log.h parsenum.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c parsenum.c

parseport.o: parseport.c parsenum.h parseport.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c parseport.c

pok-client.o: pok-client.c e.h log.h byte.h resolvehost.h \
 resolvetxtkeys.h open.h socket.h seconds.h packet.h parsenum.h \
 parseport.h parsehex.h mc.h client.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c pok-client.c

pok-makekey.o: pok-makekey.c writeall.h open.h byte.h log.h e.h mc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c pok-makekey.c

pok-server.o: pok-server.c randommod.h parseport.h writeall.h parsenum.h \
 parseip.h seconds.h socket.h packet.h server.h byte.h open.h log.h nk.h \
 mc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c pok-server.c

randommod.o: randommod.c randommod.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c randommod.c

resolvehost.o: resolvehost.c e.h log.h randommod.h resolvehost.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c resolvehost.c

resolvetxtkeys.o: resolvetxtkeys.c parsehex.h log.h byte.h e.h \
 randommod.h resolvetxtkeys.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c resolvetxtkeys.c

seconds.o: seconds.c seconds.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c seconds.c

server_phaseK0.o: server_phaseK0.c byte.h log.h nk.h mc.h packet.h \
 server.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c server_phaseK0.c

server_phaseK1.o: server_phaseK1.c packet.h byte.h log.h nk.h mc.h \
 server.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c server_phaseK1.c

server_phaseK2.o: server_phaseK2.c packet.h byte.h log.h nk.h mc.h \
 server.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c server_phaseK2.c

server_phaseK3.o: server_phaseK3.c packet.h byte.h log.h nk.h mc.h \
 server.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c server_phaseK3.c

server_phaseK4.o: server_phaseK4.c packet.h byte.h log.h nk.h mc.h \
 server.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c server_phaseK4.c

server_phaseK.o: server_phaseK.c server.h byte.h mc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c server_phaseK.c

server_phaseL.o: server_phaseL.c byte.h server.h mc.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c server_phaseL.c

socket_bind.o: socket_bind.c socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket_bind.c

socket_close.o: socket_close.c socket_queue.h socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket_close.c

socket_enqueue.o: socket_enqueue.c socket_queue.h socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket_enqueue.c

socket_poll.o: socket_poll.c log.h socket_queue.h socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket_poll.c

socket_queue.o: socket_queue.c log.h socket_queue.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket_queue.c

socket_recv.o: socket_recv.c socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket_recv.c

socket_send.o: socket_send.c socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket_send.c

socket_temperror.o: socket_temperror.c socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket_temperror.c

socket_udp.o: socket_udp.c blocking.h socket_queue.h socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket_udp.c

uint16_optblocker.o: uint16_optblocker.c cryptoint/crypto_uint16.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint16_optblocker.c

uint16_pack.o: uint16_pack.c uint16_pack.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint16_pack.c

uint16_unpack.o: uint16_unpack.c uint16_unpack.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint16_unpack.c

uint32_optblocker.o: uint32_optblocker.c cryptoint/crypto_uint32.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint32_optblocker.c

uint64_optblocker.o: uint64_optblocker.c cryptoint/crypto_uint64.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint64_optblocker.c

uint64_pack.o: uint64_pack.c uint64_pack.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint64_pack.c

uint8_optblocker.o: uint8_optblocker.c cryptoint/crypto_uint8.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint8_optblocker.c

writeall.o: writeall.c writeall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c writeall.c

OBJECTS=blocking.o
OBJECTS+=byte.o
OBJECTS+=client_downloadpk.o
OBJECTS+=client_kex.o
OBJECTS+=client_kex_query0.o
OBJECTS+=client_kex_query1.o
OBJECTS+=client_kex_query2.o
OBJECTS+=client_kex_query3.o
OBJECTS+=client_kex_query4.o
OBJECTS+=client_kex_reply0.o
OBJECTS+=client_kex_reply1.o
OBJECTS+=client_kex_reply2.o
OBJECTS+=client_kex_reply3.o
OBJECTS+=client_kex_reply4.o
OBJECTS+=client_recv.o
OBJECTS+=client_send.o
OBJECTS+=crypto_block.o
OBJECTS+=crypto_onetimeauth_poly1305.o
OBJECTS+=crypto_stream_xsalsa20.o
OBJECTS+=e.o
OBJECTS+=int16_optblocker.o
OBJECTS+=int32_optblocker.o
OBJECTS+=int64_optblocker.o
OBJECTS+=int8_optblocker.o
OBJECTS+=log.o
OBJECTS+=mc_derivekeys.o
OBJECTS+=mc_keys.o
OBJECTS+=mc_levpos.o
OBJECTS+=mc_mctiny.o
OBJECTS+=mc_pktree.o
OBJECTS+=nk.o
OBJECTS+=open_cwd.o
OBJECTS+=open_pipe.o
OBJECTS+=open_read.o
OBJECTS+=open_write.o
OBJECTS+=pacing.o
OBJECTS+=packet.o
OBJECTS+=parsehex.o
OBJECTS+=parseip.o
OBJECTS+=parsenum.o
OBJECTS+=parseport.o
OBJECTS+=randommod.o
OBJECTS+=resolvehost.o
OBJECTS+=resolvetxtkeys.o
OBJECTS+=seconds.o
OBJECTS+=server_phaseK0.o
OBJECTS+=server_phaseK1.o
OBJECTS+=server_phaseK2.o
OBJECTS+=server_phaseK3.o
OBJECTS+=server_phaseK4.o
OBJECTS+=server_phaseK.o
OBJECTS+=server_phaseL.o
OBJECTS+=socket_bind.o
OBJECTS+=socket_close.o
OBJECTS+=socket_enqueue.o
OBJECTS+=socket_poll.o
OBJECTS+=socket_queue.o
OBJECTS+=socket_recv.o
OBJECTS+=socket_send.o
OBJECTS+=socket_temperror.o
OBJECTS+=socket_udp.o
OBJECTS+=uint16_optblocker.o
OBJECTS+=uint16_pack.o
OBJECTS+=uint16_unpack.o
OBJECTS+=uint32_optblocker.o
OBJECTS+=uint64_optblocker.o
OBJECTS+=uint64_pack.o
OBJECTS+=uint8_optblocker.o
OBJECTS+=writeall.o

pok-client: pok-client.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o pok-client pok-client.o $(OBJECTS) $(LDFLAGS)

pok-makekey: pok-makekey.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o pok-makekey pok-makekey.o $(OBJECTS) $(LDFLAGS)

pok-server: pok-server.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o pok-server pok-server.o $(OBJECTS) $(LDFLAGS)


test:
	$(MAKE) test -C tests

clean:
	$(MAKE) clean -C tests
	rm -f *.o $(BINARIES)

