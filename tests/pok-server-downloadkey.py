#!/usr/bin/env python3

import socket
import binascii
import sys
import os

lev=0
pos=0

ip = sys.argv[1]
port = int(sys.argv[2])
pkhash = binascii.unhexlify(sys.argv[3])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((ip, port))
s.settimeout(1)

packet = b'PoKv0dQL'                        # magic
packet += 32 * b'\x00'                      # extension
packet += int.to_bytes(pos | (lev << 13), 2, "little") # level/position
packet += pkhash                            # hash
packet += 1158 * b'\x00'                    # padding

s.send(packet)
data = s.recv(1232)
#print(len(packet))
#print(pkhash)
#print(data[42:])
assert pkhash == data[42:]
