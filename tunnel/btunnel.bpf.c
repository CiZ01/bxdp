/* Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program shows how to use bpf_xdp_adjust_head() by
 * encapsulating the incoming packet in an IPv4/v6 header
 * and then XDP_TX it out.
 */
//#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <linux/if_tunnel.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <string.h>
#include "tunnel_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u8);
	__type(value, struct iptnl_info);
	__uint(max_entries, MAX_IPTNL_ENTRIES);
} vip2tnl SEC(".maps");


struct t_meta
{
    // unsigned short len;
    unsigned short offset;
};


static __always_inline int get_dport(void *trans_data, void *data_end,
				     __u8 protocol)
{
	struct tcphdr *th;
	struct udphdr *uh;

	switch (protocol) {
	case IPPROTO_TCP:
		th = (struct tcphdr *)trans_data;
		if (th + 1 > data_end)
			return -1;
		return th->dest;
	case IPPROTO_UDP:
		uh = (struct udphdr *)trans_data;
		if (uh + 1 > data_end)
			return -1;
		return uh->dest;
	default:
		return 0;
	}
}

static __always_inline void set_ethhdr(struct ethhdr *new_eth,
				       const struct ethhdr *old_eth,
				       const struct iptnl_info *tnl,
				       __be16 h_proto)
{
	memcpy(new_eth->h_source, old_eth->h_dest, sizeof(new_eth->h_source));
	memcpy(new_eth->h_dest, tnl->dmac, sizeof(new_eth->h_dest));
	new_eth->h_proto = h_proto;
}

static __always_inline int handle_ipv4(struct xdp_md *xdp)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct iptnl_info *tnl;
	struct ethhdr *new_eth;
	struct ethhdr *old_eth;
	struct iphdr *iph = data + sizeof(struct ethhdr);
	__u16 *next_iph___u16;
	__u16 payload_len;
	struct vip vip = {};
	int dport;
	__u32 csum = 0;
	int i;

	if (iph + 1 > data_end){
		bpf_printk("iph + 1 > data_end\n");
		return -1;
    }

	dport = get_dport(iph + 1, data_end, iph->protocol);
	if (dport == -1){
		bpf_printk("dport -1\n");
		return -1;
    }
	vip.protocol = iph->protocol;
	vip.family = AF_INET;
	vip.daddr.v4 = iph->daddr;
	vip.dport = dport;
	payload_len = ntohs(iph->tot_len);
    __u8 key = 0;
	tnl = bpf_map_lookup_elem(&vip2tnl, &key);
	/* It only does v4-in-v4 */
	// if (!tnl || tnl->family != AF_INET){
    if(!tnl){
		bpf_printk("!ntl\n");
		return -1;
    }

	/* The vip key is found.  Add an IP header and send it out */

	if (bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct iphdr))){
		bpf_printk("adj head\n");
		return -1;
    }

	data = (void *)(long)xdp->data;
	data_end = (void *)(long)xdp->data_end;

	new_eth = data;
	iph = data + sizeof(*new_eth);
	// + size(ipv4hdr) + size(ethhdr) ?
	old_eth = data + sizeof(*iph);
	//old_eth = data + sizeof(*iph) + sizeof(*new_eth);

	if (new_eth + 1 > data_end ||
	    old_eth + 1 > data_end ||
	    iph + 1 > data_end){
		bpf_printk("new_eth + 1 > data_end\n");
		return -1;
        }

	set_ethhdr(new_eth, old_eth, tnl, htons(ETH_P_IP));

	iph->version = 4;
	iph->ihl = sizeof(*iph) >> 2;
	iph->frag_off =	0;
	iph->protocol = IPPROTO_IPIP;
	iph->check = 0;
	iph->tos = 0;
	iph->tot_len = htons(payload_len + sizeof(*iph));
	iph->daddr = tnl->daddr.v4;
	iph->saddr = tnl->saddr.v4;
	iph->ttl = 8;

	next_iph___u16 = (__u16 *)iph;
#pragma clang loop unroll(full)
	for (i = 0; i < sizeof(*iph) >> 1; i++)
		csum += *next_iph___u16++;

	iph->check = ~((csum & 0xffff) + (csum >> 16));

	// count_tx(vip.protocol);
	// bpf_printk("end\n");
	return 0;
}

SEC("xdp")
int btunnel(struct xdp_md *xdp)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	void *data_meta = (void *)(long)xdp->data_meta;
    struct t_meta *md = data_meta;
    if (md + 1 > data)
    {
        return XDP_DROP + (XDP_DROP << 4);
    }
	//pkt 1

	int ret =  handle_ipv4(xdp);
	if (ret < 0){
		return XDP_DROP + (XDP_DROP << 4);
	}

	//pkt 2
	// struct ethhdr *eth2 = data + (bpf_ntohs(md->offset) & 0xFF);
	// __u16 h_proto2;

	// ret =  handle_ipv4(xdp);
	// if (ret < 0){
	// 	return XDP_DROP + (XDP_DROP << 4);
	// }

	return XDP_TX;
	
}

char _license[] SEC("license") = "GPL";