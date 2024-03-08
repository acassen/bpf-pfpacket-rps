/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Soft:        bpf_pfpacket_rps is a proof-of-concept code implementing
 * 		Receive Packet Steering (RPS) for PF_PACKET/SOCK_RAW socket.
 * 		RPS is done via socket_filter eBPF program attached to each
 * 		raw socket. This design pattern can be used for mission critical
 * 		software handling heavy loaded network traffic. For example any
 *		Layer2 access-concentrator (BNG) and any routing software dealing
 *		with ingress traffic distribution at PF_PACKET level.
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
#include <stdbool.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/ip.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <libbpf.h>
#include "data.h"

/* local var */
static const char *ifname;
static const char *bpf_rps;
static int workers_count = 1;
static int hash_alg = 0;
static uint64_t *worker_pkt;

int
if_setsockopt_rcvtimeo(int sd, int timeout)
{
	struct timeval tv;
	int ret;

	if (sd < 0)
		return sd;

	/* Set timeval */
	tv.tv_sec = timeout / 1000;
	tv.tv_usec = (timeout % 1000) * 1000;

	/* reuseaddr option */
	ret = setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (ret < 0) {
		fprintf(stderr, "%s(): cant do SO_RCVTIMEO (%m)\n"
			      , __FUNCTION__);
		close(sd);
		sd = -1;
	}

	return sd;
}

int
if_setsockopt_attach_bpf(int sd, int prog_fd)
{
	int ret;

	ret = setsockopt(sd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
	if (ret < 0) {
		fprintf(stderr, "%s(): Error attaching eBPF program to socket (%m)\n"
			      , __FUNCTION__);
		return -1;
	}

	return sd;
}

static struct bpf_object *
bpf_rps_filter_init(worker_t *w, int fd, const char *filename)
{
	struct bpf_object *bpf_obj;
	struct bpf_program *bpf_prog;
	struct bpf_map *bpf_map;
	struct rps_id value;
	char errmsg[BPF_STRERR_BUFSIZE];
	int err, key = 0;

	bpf_obj = bpf_object__open(filename);
	if (!bpf_obj) {
		libbpf_strerror(errno, errmsg, BPF_STRERR_BUFSIZE);
		fprintf(stderr, "eBPF: error opening bpf file err:%d (%s)\n"
			      , errno, errmsg);
		return NULL;
	}

	bpf_prog = bpf_object__next_program(bpf_obj, NULL);
	if (!bpf_prog) {
		fprintf(stderr, "eBPF: no program found in file:%s\n", filename);
		bpf_object__close(bpf_obj);
		return NULL;
	}
	bpf_program__set_type(bpf_prog, BPF_PROG_TYPE_SOCKET_FILTER);

	err = bpf_object__load(bpf_obj);
	if (err) {
		libbpf_strerror(err, errmsg, BPF_STRERR_BUFSIZE);
		fprintf(stderr, "eBPF: error loading bpf_object err:%d (%s)\n"
			      , err, errmsg);
		bpf_object__close(bpf_obj);
		return NULL;
	}

	bpf_map = bpf_object__find_map_by_name(bpf_obj, "socket_filter_ops");
	if (!bpf_map) {
		fprintf(stderr, "eBPF: error mapping:%s\n"
			      , "socket_filter_ops");
		bpf_object__close(bpf_obj);
		return NULL;
	}

	err = if_setsockopt_attach_bpf(fd, bpf_program__fd(bpf_prog));
	if (err < 0) {
		bpf_object__close(bpf_obj);
		return NULL;
	}

	/* Initialize socket filter option */
	memset(&value, 0, sizeof(struct rps_id));
	value.id = w->id;
	value.max_id = workers_count;
	value.alg = hash_alg;
	err = bpf_map__update_elem(bpf_map, &key, sizeof(int)
					  , &value, sizeof(struct rps_id)
					  , BPF_ANY);
	if (err) {
		libbpf_strerror(errno, errmsg, BPF_STRERR_BUFSIZE);
		fprintf(stderr, "eBPF: error setting option in map:%s (%s)\n"
			      , "socket_filter_ops", errmsg);
		bpf_object__close(bpf_obj);
		return NULL;
	}

	return bpf_obj;
}

static int
socket_init(const char *ifname, uint16_t proto)
{
	struct sockaddr_ll sll;
	int fd, ret;

	fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(proto));
	fd = if_setsockopt_rcvtimeo(fd, 3000);
	if (fd < 0) {
		fprintf(stderr, "%s(): Error creating socket channel on interface %s (%m)\n"
			      , __FUNCTION__
			      , ifname);
		return -1;
	}

	memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family = PF_PACKET;
	sll.sll_protocol = htons(proto);
	sll.sll_ifindex = if_nametoindex(ifname);
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

static void *
worker_task(void *arg)
{
	worker_t *w = arg;
	struct bpf_object *bpf_obj;
	char pname[128];
	ssize_t nbytes;
	int fd;

	/* Our identity */
	snprintf(pname, 127, "w-%d ", w->id);
	prctl(PR_SET_NAME, pname, 0, 0, 0, 0);

	/* Socket init */
	fd = socket_init(ifname, ETH_P_PPP_DISC);
	if (fd < 0)
		return NULL;

	/* BPF related */
	if (bpf_rps) {
		bpf_obj = bpf_rps_filter_init(w, fd, bpf_rps);
		if (!bpf_obj) {
			close(fd);
			return NULL;
		}
	}

	for (;;) {
		nbytes = recv(fd, w->buffer, BUFFER_SIZE, 0);
		if (nbytes < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;

			fprintf(stderr, "W-%d: Error receiving on socket (%m)\n", w->id);
			break;
		}

		worker_pkt[w->id]++;
	}

	return NULL;
}

static double
std_deviation(void)
{
	double avg = 0.0, gap = 0.0;
	int i;

	for (i = 0; i < workers_count; i++)
		avg += worker_pkt[i];
	avg /= workers_count;

	for (i = 0; i < workers_count; i++)
		gap += pow((avg - worker_pkt[i]), 2);
	gap /= workers_count;

	return sqrt(gap);
}

static void *
worker_stats_task(void *arg)
{
	int i, total;

	for (;;) {
		total = 0;
		for (i = 0; i < workers_count; i++) {
			total += worker_pkt[i];
			printf("#%d:%.4ld ", i, worker_pkt[i]);
		}
		printf("(total:%d std_dev:%f)\n", total, std_deviation());
		sleep(1);
	}

	return NULL;
}
	

static int
worker_init(worker_t *w, int id)
{
	w->id = id;
	pthread_create(&w->task, NULL, worker_task, w);
	return 0;
}

static int
workers_start(void)
{
	worker_t *w;
	int i;

	/* Allocate Worker */
	w = (worker_t *) malloc(sizeof(worker_t) * workers_count);
	memset(w, 0, sizeof(worker_t) * workers_count);
	for (i = 0; i < workers_count; i++)
		worker_init(&w[i], i);

	return 0;
}

/*
 *	Usage function
 */
static void
usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [OPTION...]\n", prog);
	fprintf(stderr, "  -i, --bind-interface		Interface to bind to\n");
	fprintf(stderr, "  -w, --worker-count		Number of thread workers\n");
	fprintf(stderr, "  -a, --hash-alg		0:mac_hash 1:mac_jhash 2:jhash_oaat\n");
	fprintf(stderr, "  -b, --ebpf-rps		eBPF RPS program\n");
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

	struct option long_options[] = {
		{"bind-interface",	optional_argument,	NULL, 'i'},
		{"worker-count",	optional_argument,	NULL, 'w'},
		{"hash-alg",		optional_argument,	NULL, 'a'},
		{"ebpf-rps",		optional_argument,	NULL, 'b'},
		{"help",                no_argument,		NULL, 'h'},
		{NULL,                  0,			NULL,  0 }
	};

	curind = optind;
	while (longindex = -1, (c = getopt_long(argc, argv, ":hi:w:a:b:"
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
		case 'w':
			workers_count = atoi(optarg);
                        break;
		case 'a':
			hash_alg = atoi(optarg);
                        break;
		case 'b':
			bpf_rps = optarg;
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

	if (bad_option)
		exit(1);

	worker_pkt = malloc(sizeof(uint64_t) * (workers_count));
	memset(worker_pkt, 0, sizeof(uint64_t) * (workers_count));
	return 0;
}


/*
 *	Main point
 */
int
main(int argc, char **argv)
{
	pthread_t stats_task;

	parse_cmdline(argc, argv);
	pthread_create(&stats_task, NULL, worker_stats_task, NULL);
	workers_start();
	for (;;) sleep(1);

	exit(0);
}
