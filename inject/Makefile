# SPDX-License-Identifier: GPL-2.0-or-later
#
# Soft:        bpf_pfpacket_rps is a proof-of-concept code implementing
#              Receive Packet Steering (RPS) for PF_PACKET/SOCK_RAW socket.
#              RPS is done via socket_filter eBPF program attached to each
#              raw socket. This design pattern can be used for mission critical
#              software handling heavy loaded network traffic. For example any
#              Layer2 access-concentrator (BNG) and any routing software dealing
#              with ingress traffic distribution at PF_PACKET level.
#
# Author:      Alexandre Cassen, <acassen@gmail.com>
#
#              This program is distributed in the hope that it will be useful,
#              but WITHOUT ANY WARRANTY; without even the implied warranty of
#              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#              See the GNU General Public License for more details.
#
#              This program is free software; you can redistribute it and/or
#              modify it under the terms of the GNU General Public License
#              as published by the Free Software Foundation; either version
#              2 of the License, or (at your option) any later version.
#
# Copyright (C) 2024 Alexandre Cassen, <acassen@gmail.com>
#

EXEC= inject
BIN  = ../bin

CC= gcc
CFLAGS= -Wall -Wstrict-prototypes -Wpointer-arith -O3 -fomit-frame-pointer -fexpensive-optimizations
LDLIBS= 
OBJECTS= main.o
.c.o:	
	$(CC) -o $@ $(CFLAGS) -c $*.c

all:	$(EXEC)
	@echo ""
	@echo "Make complete"

$(EXEC):	$(OBJECTS)
	$(CC) -o $(BIN)/$(EXEC) $(CFLAGS) $(OBJECTS) $(LDLIBS)

clean:
	-rm -f *.o $(BIN)/$(EXEC) 

