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

EXEC = bpf_pfpacket_rps
BIN  = bin

CC        ?= gcc
LDFLAGS   = -lpthread -lcrypt -ggdb -lm -lz -lresolv -lelf
SUBDIRS   = src
LIBBPF    = libbpf
OBJDIR    = $(LIBBPF)/src

all: $(OBJDIR)/libbpf.a
	@set -e; \
	for i in $(SUBDIRS); do \
	$(MAKE) -C $$i || exit 1; done && \
	echo "Building $(BIN)/$(EXEC)" && \
	$(CC) -o $(BIN)/$(EXEC) `find $(SUBDIRS) -name '*.[oa]'` $(OBJDIR)/libbpf.a $(LDFLAGS)
	$(MAKE) -C inject
	$(MAKE) -C src/bpf
	@echo ""
	@echo "Make complete"

$(OBJDIR)/libbpf.a:
	@$(MAKE) -C $(LIBBPF)/src BUILD_STATIC_ONLY=y NO_PKG_CONFIG=y
	@ln -sf ../include/uapi $(OBJDIR)

clean:
	@$(MAKE) -C $(LIBBPF)/src clean
	rm -f $(OBJDIR)/uapi
	@set -e; \
	for i in $(SUBDIRS); do \
	$(MAKE) -C $$i clean; done
	$(MAKE) -C inject clean
	$(MAKE) -C src/bpf clean
	rm -f $(BIN)/$(EXEC)
	@echo ""
	@echo "Make complete"
