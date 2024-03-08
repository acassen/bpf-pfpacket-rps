/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Soft:        bpf_pfpacket_rps is a proof-of-concept code implementing
 *              Receive Packet Steering (RPS) for PF_PACKET/SOCK_RAW socket.
 *              RPS is done via socket_filter eBPF program attached to each
 *              raw socket. This design pattern can be used for mission critical
 *              software handling heavy loaded network traffic. For example any
 *              Layer2 access-concentrator (BNG) and any routing software dealing
 *              with ingress traffic distribution at PF_PACKET level.
 *
 * Author:      Alexandre Cassen, <acassen@gmail.com>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2024 Alexandre Cassen, <acassen@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

/* local var */
static char *ifname;
static int pkt_count = 1;

typedef struct _pppoe_hdr {
        uint8_t         vertype;
        uint8_t         code;
        uint16_t        session;
        uint16_t        plen;
} __attribute__((packed)) pppoe_hdr_t;

/*
 *	Packet building
 */
static const struct ether_addr hw_src = {{0x02, 0x00, 0x01, 0x01, 0x01, 0x01}};
static struct ether_addr hw_dst;

static size_t
packet_prepare(char *buffer, size_t size, uint16_t proto)
{
	struct ether_header *eh;
	pppoe_hdr_t *pppoeh;
	size_t offset = 0;

	/* Ethernet Header */
	eh = (struct ether_header *) buffer;
	memcpy(eh->ether_dhost, &hw_dst, ETH_ALEN);
	memcpy(eh->ether_shost, &hw_src, ETH_ALEN);
	eh->ether_type = htons(proto);
	offset += sizeof(struct ether_header);

	/* PPPoE Header */
	pppoeh = (pppoe_hdr_t *) (buffer + offset);
	pppoeh->vertype = 0x11;
	pppoeh->code = 0x00;
	pppoeh->session = htons(0xcafe);
	pppoeh->plen = htons(128);
	offset += sizeof(pppoe_hdr_t);

	/* Some Bulk data */
	memset(buffer + offset, 0xff, 128);
	offset += 128;

	return offset;
}


/*
 *	Socket related
 */
static int
socket_init(const char *ifname, uint16_t proto)
{
        struct sockaddr_ll sll;
        int fd, ret;

        memset(&sll, 0, sizeof(struct sockaddr_ll));
        sll.sll_family = PF_PACKET;
        sll.sll_protocol = htons(proto);
        sll.sll_ifindex = if_nametoindex(ifname);

        fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(proto));
        if (fd < 0) {
                fprintf(stderr, "%s(): Error creating socket channel on interface %s (%m)\n"
                              , __FUNCTION__
                              , ifname);
                return -1;
        }

        ret = bind(fd, (struct sockaddr *) &sll, sizeof(sll));
        if (ret < 0) {
                fprintf(stderr, "%s(): Error binding channel on interface %s (%m)\n"
                              , __FUNCTION__
                              , ifname);
                close(fd);
                return -1;
        }

        return fd;
}

uint32_t
poor_prng(unsigned int *seed)
{
        uint32_t shuffle;

        shuffle = rand_r(seed) & 0xff;
        shuffle |= (rand_r(seed) & 0xff) << 8;
        shuffle |= (rand_r(seed) & 0xff) << 16;
        shuffle |= (rand_r(seed) & 0xff) << 24;

        return shuffle;
}

static int
inject_run(const char *ifname)
{
	struct ether_header *eh;
	char buffer[4096];
	size_t nbytes;
	int fd, i, ret;
	unsigned int seed = time(NULL);

	fd = socket_init(ifname, ETH_P_PPP_DISC);
	if (fd < 0)
		return -1;

	nbytes = packet_prepare(buffer, 4096, ETH_P_PPP_DISC);
	eh = (struct ether_header *) buffer;

	for (i = 0; i < pkt_count; i++) {
		eh->ether_shost[1] += poor_prng(&seed);
		eh->ether_shost[2] += poor_prng(&seed);
		eh->ether_shost[3] += poor_prng(&seed);
		eh->ether_shost[4] += poor_prng(&seed);
		eh->ether_shost[5] += poor_prng(&seed);
#if 0
		printf("hw_src %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
			eh->ether_shost[0],
			eh->ether_shost[1],
			eh->ether_shost[2],
			eh->ether_shost[3],
			eh->ether_shost[4],
			eh->ether_shost[5]);
#endif
		ret = send(fd, buffer, nbytes, 0);
		if (ret < 0) {
			fprintf(stderr, "Error sending packet(%m)\n");
		}
		usleep(20);
	}

	return 0;
}


/*
 *	Usage function
 */
static void
usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [OPTION...]\n", prog);
	fprintf(stderr, "  -i, --bind-interface 	Interface to bind to\n");
	fprintf(stderr, "  -d, --dest-mac	 	Destination MAC Address\n");
	fprintf(stderr, "  -p, --pkt-count	 	Number of packet to send\n");
	fprintf(stderr, "  -h, --help			Display this help message\n");
}


/*
 *	Command line parser
 */
static int
parse_cmdline(int argc, char **argv)
{
	int c, longindex, curind;
	int bad_option = 0;
	int v[ETH_ALEN], i = 0;

	struct option long_options[] = {
		{"bind-interface",	required_argument,	NULL, 'i'},
		{"dest-mac",		optional_argument,	NULL, 'd'},
		{"pkt-count",		optional_argument,	NULL, 'p'},
		{"help",                no_argument,		NULL, 'h'},
		{NULL,                  0,			NULL,  0 }
	};

	curind = optind;
	while (longindex = -1, (c = getopt_long(argc, argv, ":hi:d:p:"
						, long_options, &longindex)) != -1) {
		if (longindex >= 0 && long_options[longindex].has_arg == required_argument &&
		    optarg && !optarg[0]) {
			c = ':';
			optarg = NULL;
		}

		switch (c) {
		case 'h':
			usage(argv[0]);
			exit(0);
                        break;
		case 'i':
			ifname = optarg;
                        break;
		case 'd':
			sscanf(optarg, "%x:%x:%x:%x:%x:%x%*c"
				     , &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
			for (i = 0; i < ETH_ALEN; i++)
				hw_dst.ether_addr_octet[i] = (uint8_t) v[i];
			break;
		case 'p':
			pkt_count = atoi(optarg);
                        break;
		case '?':
			if (optopt && argv[curind][1] != '-')
				fprintf(stderr, "Unknown option -%c\n", optopt);
			else
				fprintf(stderr, "Unknown option --%s\n", argv[curind]);
			bad_option = 1;
			break;
		case ':':
			if (optopt && argv[curind][1] != '-')
				fprintf(stderr, "Missing parameter for option -%c\n", optopt);
			else
				fprintf(stderr, "Missing parameter for option --%s\n", long_options[longindex].name);
			bad_option = 1;
			break;
		default:
			exit(1);
			break;
		}
                curind = optind;
	}

	if (optind < argc) {
		printf("Unexpected argument(s): ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
	}

	if (!ifname) {
		fprintf(stderr, "You MUST provide an ifname !!!\n\n");
		usage(argv[0]);
		exit(1);
	}

	if (!i) {
		fprintf(stderr, "You MUST provide an destination MAC Address !!!\n\n");
		usage(argv[0]);
		exit(1);
	}

	if (bad_option)
		exit(1);

	return 0;
}


/*
 *	Main point
 */
int
main(int argc, char **argv)
{
	/* Command line parsing */
	parse_cmdline(argc, argv);

	/* Inject */
	inject_run(ifname);

	exit(0);
}
