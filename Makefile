CC?=cc
CFLAGS+=-W -Wall -Os -fPIC -fwrapv -pedantic -DSOCKET_QUEUE=1
LDFLAGS+=-lmceliece -lrandombytes

BINARIES=pok-client
BINARIES+=pok-forwarder
BINARIES+=pok-makekey
BINARIES+=pok-server

all: $(BINARIES)

blocking.o: blocking.c blocking.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c blocking.c

byte_copy.o: byte_copy.c byte.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c byte_copy.c

byte_isequal.o: byte_isequal.c byte.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c byte_isequal.c

byte_zero.o: byte_zero.c byte.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c byte_zero.c

client_connect.o: client_connect.c pacing.h seconds.h log.h byte.h mc.h \
 mc_variants.h extension.h socket.h randommod.h client.h packet.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_connect.c

client_query0.o: client_query0.c log.h byte.h socket.h packet.h client.h \
 mc.h mc_variants.h extension.h pacing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_query0.c

client_query1.o: client_query1.c log.h byte.h socket.h packet.h client.h \
 mc.h mc_variants.h extension.h pacing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_query1.c

client_query2.o: client_query2.c log.h byte.h socket.h packet.h client.h \
 mc.h mc_variants.h extension.h pacing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_query2.c

client_query3.o: client_query3.c log.h byte.h packet.h socket.h client.h \
 mc.h mc_variants.h extension.h pacing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_query3.c

client_queryM.o: client_queryM.c uint64_pack.h log.h byte.h packet.h \
 socket.h seconds.h client.h mc.h mc_variants.h extension.h pacing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_queryM.c

client_reply0.o: client_reply0.c log.h byte.h packet.h client.h mc.h \
 mc_variants.h extension.h pacing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_reply0.c

client_reply1.o: client_reply1.c log.h byte.h packet.h client.h mc.h \
 mc_variants.h extension.h pacing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_reply1.c

client_reply2.o: client_reply2.c log.h byte.h packet.h client.h mc.h \
 mc_variants.h extension.h pacing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_reply2.c

client_reply3.o: client_reply3.c log.h byte.h packet.h client.h mc.h \
 mc_variants.h extension.h pacing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_reply3.c

client_replyM.o: client_replyM.c uint64_unpack.h log.h byte.h packet.h \
 seconds.h client.h mc.h mc_variants.h extension.h pacing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c client_replyM.c

crypto_block.o: crypto_block.c crypto_block.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_block.c

crypto_onetimeauth_poly1305.o: crypto_onetimeauth_poly1305.c \
 crypto_onetimeauth_poly1305.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_onetimeauth_poly1305.c

crypto_stream_xsalsa20.o: crypto_stream_xsalsa20.c \
 crypto_stream_xsalsa20.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_stream_xsalsa20.c

dupforkexec.o: dupforkexec.c log.h blocking.h dupforkexec.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dupforkexec.c

e.o: e.c e.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c e.c

extension.o: extension.c parseip.h byte.h mc.h mc_variants.h extension.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c extension.c

log.o: log.c e.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c log.c

mc.o: mc.c seconds.h log.h mc.h mc_variants.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c mc.c

mc_keys.o: mc_keys.c parsehex.h log.h mc.h mc_variants.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c mc_keys.c

mc_mctiny.o: mc_mctiny.c crypto_stream_xsalsa20.h log.h mc.h \
 mc_variants.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c mc_mctiny.c

mc_variants.o: mc_variants.c mc.h mc_variants.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c mc_variants.c

message.o: message.c byte.h uint8_pack.h uint8_unpack.h uint16_pack.h \
 uint16_unpack.h uint32_pack.h uint32_unpack.h uint64_pack.h \
 uint64_unpack.h log.h pacing.h dupforkexec.h seconds.h randommod.h \
 blocking.h socket.h message.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c message.c

message_log.o: message_log.c message.h log.h uint64_unpack.h \
 uint32_unpack.h uint16_unpack.h uint8_unpack.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c message_log.c

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
 crypto_onetimeauth_poly1305.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c packet.c

parsehex.o: parsehex.c parsehex.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c parsehex.c

parseip.o: parseip.c log.h parseip.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c parseip.c

parsenum.o: parsenum.c log.h parsenum.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c parsenum.c

parseport.o: parseport.c log.h parsenum.h parseport.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c parseport.c

pok-client.o: pok-client.c log.h byte.h resolvehost.h open.h socket.h \
 seconds.h message.h uint64_pack.h uint64_unpack.h packet.h mc.h \
 mc_variants.h parsenum.h parseport.h extension.h client.h pacing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c pok-client.c

pok-forwarder.o: pok-forwarder.c log.h byte.h socket.h parseip.h \
 parseport.h mc.h mc_variants.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c pok-forwarder.c

pok-makekey.o: pok-makekey.c open.h writeall.h mc.h mc_variants.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c pok-makekey.c

pok-server.o: pok-server.c nk.h seconds.h byte.h open.h randommod.h \
 server.h extension.h mc.h mc_variants.h packet.h message.h log.h \
 parseip.h parsenum.h parseport.h blocking.h writeall.h socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c pok-server.c

randommod.o: randommod.c randommod.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c randommod.c

resolvehost.o: resolvehost.c e.h log.h randommod.h resolvehost.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c resolvehost.c

seconds.o: seconds.c seconds.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c seconds.c

server_phase0.o: server_phase0.c byte.h log.h nk.h mc.h mc_variants.h \
 packet.h server.h extension.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c server_phase0.c

server_phase1.o: server_phase1.c packet.h byte.h log.h nk.h mc.h \
 mc_variants.h server.h extension.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c server_phase1.c

server_phase2.o: server_phase2.c packet.h byte.h log.h nk.h mc.h \
 mc_variants.h server.h extension.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c server_phase2.c

server_phase3.o: server_phase3.c packet.h byte.h log.h nk.h mc.h \
 mc_variants.h server.h extension.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c server_phase3.c

server_phaseM.o: server_phaseM.c packet.h byte.h uint64_pack.h \
 uint64_unpack.h seconds.h log.h server.h extension.h mc.h mc_variants.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c server_phaseM.c

socket_bind.o: socket_bind.c socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket_bind.c

socket_close.o: socket_close.c socket_queue.h socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket_close.c

socket_enqueue.o: socket_enqueue.c socket_queue.h socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket_enqueue.c

socket_pair.o: socket_pair.c blocking.h socket_queue.h socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket_pair.c

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

uint16_pack.o: uint16_pack.c uint16_pack.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint16_pack.c

uint16_unpack.o: uint16_unpack.c uint16_unpack.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint16_unpack.c

uint32_pack.o: uint32_pack.c uint32_pack.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint32_pack.c

uint32_unpack.o: uint32_unpack.c uint32_unpack.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint32_unpack.c

uint64_pack.o: uint64_pack.c uint64_pack.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint64_pack.c

uint64_unpack.o: uint64_unpack.c uint64_unpack.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint64_unpack.c

uint8_pack.o: uint8_pack.c uint8_pack.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint8_pack.c

uint8_unpack.o: uint8_unpack.c uint8_unpack.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint8_unpack.c

writeall.o: writeall.c writeall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c writeall.c

OBJECTS=blocking.o
OBJECTS+=byte_copy.o
OBJECTS+=byte_isequal.o
OBJECTS+=byte_zero.o
OBJECTS+=client_connect.o
OBJECTS+=client_query0.o
OBJECTS+=client_query1.o
OBJECTS+=client_query2.o
OBJECTS+=client_query3.o
OBJECTS+=client_queryM.o
OBJECTS+=client_reply0.o
OBJECTS+=client_reply1.o
OBJECTS+=client_reply2.o
OBJECTS+=client_reply3.o
OBJECTS+=client_replyM.o
OBJECTS+=crypto_block.o
OBJECTS+=crypto_onetimeauth_poly1305.o
OBJECTS+=crypto_stream_xsalsa20.o
OBJECTS+=dupforkexec.o
OBJECTS+=e.o
OBJECTS+=extension.o
OBJECTS+=log.o
OBJECTS+=mc.o
OBJECTS+=mc_keys.o
OBJECTS+=mc_mctiny.o
OBJECTS+=mc_variants.o
OBJECTS+=message.o
OBJECTS+=message_log.o
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
OBJECTS+=seconds.o
OBJECTS+=server_phase0.o
OBJECTS+=server_phase1.o
OBJECTS+=server_phase2.o
OBJECTS+=server_phase3.o
OBJECTS+=server_phaseM.o
OBJECTS+=socket_bind.o
OBJECTS+=socket_close.o
OBJECTS+=socket_enqueue.o
OBJECTS+=socket_pair.o
OBJECTS+=socket_poll.o
OBJECTS+=socket_queue.o
OBJECTS+=socket_recv.o
OBJECTS+=socket_send.o
OBJECTS+=socket_temperror.o
OBJECTS+=socket_udp.o
OBJECTS+=uint16_pack.o
OBJECTS+=uint16_unpack.o
OBJECTS+=uint32_pack.o
OBJECTS+=uint32_unpack.o
OBJECTS+=uint64_pack.o
OBJECTS+=uint64_unpack.o
OBJECTS+=uint8_pack.o
OBJECTS+=uint8_unpack.o
OBJECTS+=writeall.o

pok-client: pok-client.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o pok-client pok-client.o $(OBJECTS) $(LDFLAGS)

pok-forwarder: pok-forwarder.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o pok-forwarder pok-forwarder.o $(OBJECTS) $(LDFLAGS)

pok-makekey: pok-makekey.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o pok-makekey pok-makekey.o $(OBJECTS) $(LDFLAGS)

pok-server: pok-server.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o pok-server pok-server.o $(OBJECTS) $(LDFLAGS)


test: all
	sh pok-test.sh

clean:
	rm -f *.o $(BINARIES)

