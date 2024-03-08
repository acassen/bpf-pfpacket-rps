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

#define KBUILD_MODNAME "bpf_rps"
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <uapi/linux/bpf.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include "jhash.h"

struct rps_id {
        __u16   id;
        __u16   max_id;
	__u32	alg;
} __attribute__ ((__aligned__(8)));

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, int);
        __type(value, struct rps_id);
} socket_filter_ops SEC(".maps");


/* Distribution of random mac over 8 buckets:
 * #0:3097 #1:3215 #2:3258 #3:3091 #4:3132 #5:3103 #6:3063 #7:3041 (total:25000 std_dev:69.966063)
 */
static __always_inline __u32
jhash_oaat(const __u8 *hw, const int size)
{
	__u32 hash = JHASH_INITVAL;
	int i = 0;

	while (i < size) {
		hash += hw[i++];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return hash;
}

/* Distribution of random mac over 8 buckets:
 * #0:3178 #1:3078 #2:3144 #3:3123 #4:3068 #5:3055 #6:3118 #7:3236 (total:25000 std_dev:56.901230)
 */
static __always_inline __u32
mac_jhash(const void *hw)
{
	__u32 hbits = *(__u32 *) hw;
	__u16 lbits = *(__u16 *) (hw + 4);

	return jhash_2words(hbits, lbits, 0);
}

/* Distribution of random mac over 8 buckets:
 * #0:3155 #1:3119 #2:3142 #3:3110 #4:3108 #5:3098 #6:3177 #7:3091 (total:25000 std_dev:28.124722)
 * This one is the best for MAC Address hashing regarding
 * complexity and distribution.
 */
static __always_inline __u32
mac_hash(const __u8 *hw, const int size)
{
	int i = 0;
	__u32 hash = 0;

	while (i < size)
		hash = (hash << 8) | hw[i++];
	return hash;
}


SEC("socket_filter")
int sock_raw_rps(struct __sk_buff *skb)
{
	struct rps_id *value;
	int idx = 0;
	__u8 hw_src[ETH_ALEN];
	__u32 hkey;

	value = bpf_map_lookup_elem(&socket_filter_ops, &idx);
	if (!value)
		return 0;

	/* "Direct Packet Access" via sock_filter just have limited support
	 * for security reasons since most of sock_filter are mostly run in
	 * unprivileged env. So we need to load at least hw_src in context.
	 * Tested with CAP_BPF & CAP_PERFMON which didnt enable DPA :/
	 */
	bpf_skb_load_bytes(skb, ETH_ALEN, &hw_src, ETH_ALEN);
	if (value->alg == 2)
		hkey = jhash_oaat(hw_src, ETH_ALEN) & (value->max_id - 1);
	else if (value->alg == 1)
		hkey = mac_jhash(hw_src) & (value->max_id - 1);
	else
		hkey = mac_hash(hw_src, ETH_ALEN) & (value->max_id - 1);

	return (hkey == value->id) ? 1 : 0;
}

char _license[] SEC("license") = "GPL";
