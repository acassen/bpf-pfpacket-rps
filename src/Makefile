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

CC       ?= gcc
INCLUDES = -I../libbpf/src -I../libbpf/src/uapi
CFLAGS   = -g -O2 -ggdb $(INCLUDES) -Werror -Wall -Wunused -Wstrict-prototypes -D_GNU_SOURCE
DEFS     =
COMPILE  = $(CC) $(CFLAGS) $(DEFS)

OBJS =  main.o

HEADERS = $(OBJS:.o=.h)

.c.o:
	@echo "  CC" $@
	@$(COMPILE) -c $<

all:    $(OBJS)

clean:
	rm -f *.a *.o *~

