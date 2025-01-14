/*
 * Copyright 2021 Sebastiano Miano <mianosebastiano@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "fasthash.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

void xxhash32(const __u8 *buf, const __u32 seed, __u8 *out) __ksym;

#define _SEED_HASHFN 77

#define HASHFN_N 4
#define COLUMNS 1048576

struct countmin {
  __u64 values[HASHFN_N][COLUMNS];
};

struct pkt_5tuple {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  __u32 proto;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct countmin);
} countmin SEC(".maps");

static __always_inline void hash(const struct pkt_5tuple *pkt,
                                 __u64 hashes[4][4]) {
  __u8 h[sizeof(struct pkt_5tuple) * 4];
  xxhash32((__u8 *)pkt, 0, (__u8 *)h);
  __u64 *h64 = (__u64 *)h;

  // bpf_printk("non crash: %x\n %x\n %x\n %x\n", h[0], h[1], h[2], h[3]);
  // bpf_printk("hashe:ws:\n%x\n %x\n %x\n %x\n", h[0], h[1], h[2], h[3]);
  for (int i = 0; i < 4; i++) {
    hashes[0] = (h64[0] & 0xFFFF);
    hashes[1] = h64[i][1] >> 16 & 0xFFF;
    hashes[2] = h64[i][2] >> 32 & 0xFFF;
    hashes[3] = h64[i][3] >> 48 & 0xFFF;
  }
  return;
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static __always_inline void countmin_add(struct countmin *cm,
                                         const __u32 hashes[4][4]) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      __u32 target_idx = hashes[i][j] & (COLUMNS - 1);
      //__sync_fetch_and_add(&cm->values[i][target_idx], 1); //;< -this crash
      // clang
      cm->values[i][target_idx]++;
    }
  }
  return;
}

static __always_inline int handle_pkt(void *data, void *data_end,
                                      struct pkt_5tuple *pkt) {
  struct ethhdr *eth = data;
  if (eth + 1 >= data_end)
    return XDP_DROP;

  __u16 h_proto = eth->h_proto;

  switch (h_proto) {
  case bpf_htons(ETH_P_IP):
    break;
  default:
    return XDP_DROP;
  }

  struct iphdr *ip = data + sizeof(struct ethhdr);
  if (ip + 1 >= data_end)
    return XDP_DROP;
  pkt->src_ip = ip->saddr;
  pkt->dst_ip = ip->daddr;
  pkt->proto = ip->protocol;
  switch (ip->protocol) {
  case IPPROTO_TCP: {
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (tcp + 1 > data_end)
      return XDP_DROP;
    pkt->src_port = tcp->source;
    pkt->dst_port = tcp->dest;
    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (udp + 1 > data_end)
      return XDP_DROP;
    pkt->src_port = udp->source;
    pkt->dst_port = udp->dest;
    break;
  }
  default:
    return XDP_DROP;
  }
  return 0;
}

SEC("xdp")
int hbcms(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  __u32 zero = 0;
  struct countmin *cm = bpf_map_lookup_elem(&countmin, &zero);
  if (!cm)
    return XDP_DROP;

  struct pkt_5tuple pkts[4];
  __u64 pkts_hashes[4][4] = {0};
  for (int i = 0; i < 4; i++) {
    int ret = handle_pkt(data, data_end, &pkts[i]);
    if (ret)
      return ret;
  }
  // print pkts buf
  hash(pkts, pkts_hashes);
  countmin_add(cm, pkts_hashes);
  return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
