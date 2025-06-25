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
void xxhash16x4(const __u64 *buf, const __u32 seed, __u8 *out) __ksym;

struct t_meta {
  unsigned short valid;
  unsigned short len1;
  unsigned short len2;
  unsigned short len3;
};

#define _SEED_HASHFN 77

#define HASHFN_N 4
#define COLUMNS 1048576
#define MAX_GEOSAMPLING_SIZE 4096

struct countmin {
  __u64 values[HASHFN_N][COLUMNS];
};

struct pkt_5tuple {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  __u8 proto;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct countmin);
} countmin SEC(".maps");

struct geosampling {
  __u32 geo_sampling_array[MAX_GEOSAMPLING_SIZE];
  __u32 geo_sampling_idx;
  __u32 count;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct geosampling);
} geosampling SEC(".maps");

static __always_inline void hash(const struct pkt_5tuple *pkt,
                                 __u16 hashes[4][4]) {
  __u64 h[8] = {0}; // 512 bit

  xxhash16x4((__u64 *)pkt, 0, (__u8 *)h);
  int j = 0;
  for (int i = 0; i < 4; i++) {
    hashes[i][0] = h[j] & 0xFFFF;
    hashes[i][1] = h[j] >> 16 & 0xFFFF;
    hashes[i][2] = h[j] >> 32 & 0xFFFF;
    hashes[i][3] = h[j] >> 48 & 0xFFFF;
    j+=2;
  }
  return;
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static __always_inline void
nitro_add(struct countmin *cm, const __u16 hashes[4], __u32 row_to_update) {

  if (row_to_update >= HASHFN_N)
    return;
  __u16 hash = hashes[row_to_update];
  __u16 target_idx = hash & (COLUMNS - 1);

  cm->values[row_to_update][target_idx]++;

  return;
}

static __always_inline void nitro_update(struct countmin *cm,
                                         const __u16 hashes[4],
                                         struct geosampling *geo,
                                         __u32 row_to_update,
                                         __u32 next_geo_value) {
  // __u32 next_geo_value;
  // __u32 row_to_update = geo->count;

  for (int i = 0; i < HASHFN_N; i++) {
    nitro_add(cm, hashes, row_to_update);

    __u32 geo_value_idx = geo->geo_sampling_idx;
    geo_value_idx = (geo_value_idx + 1) & (MAX_GEOSAMPLING_SIZE - 1);
    next_geo_value = geo->geo_sampling_array[geo_value_idx];
    row_to_update += next_geo_value;
    geo->geo_sampling_idx = geo_value_idx;

    if (row_to_update >= HASHFN_N)
      break;
  }

  if (next_geo_value > 0) {
    geo->count = next_geo_value - 1;
  } else {
    bpf_printk("Geo sammpling variable is 0. This should never happen");
  }
}
static __always_inline int handle_pkt(void *data, void *data_end,
                                      struct pkt_5tuple *pkt) {
  struct ethhdr *eth = data;
  if (eth + 1 >= data_end) {
    bpf_printk("eth + 1 >= data_end\n");
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }

  __u16 h_proto = eth->h_proto;

  switch (h_proto) {
  case bpf_htons(ETH_P_IP):
    break;
  default:
    bpf_printk("eth\n");
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }

  struct iphdr *ip = data + sizeof(struct ethhdr);
  if ((void *)(ip + 1) >= data_end)
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  pkt->src_ip = ip->saddr;
  pkt->dst_ip = ip->daddr;
  pkt->proto = ip->protocol;
  // bpf_printk("src_ip: %pI4\n", &ip->saddr);
  switch (ip->protocol) {
  case IPPROTO_TCP: {
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (tcp + 1 > data_end)
      return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    pkt->src_port = tcp->source;
    pkt->dst_port = tcp->dest;
    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void *)(udp + 1) > data_end) {
      bpf_printk("udp\n");
      return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }
    pkt->src_port = udp->source;
    pkt->dst_port = udp->dest;
    break;
  }
  default:
    bpf_printk("proto\n");
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }
  return 0;
}

SEC("xdp")
int abnitro2(struct xdp_md *ctx) {

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  void *data_meta = (void *)(long)ctx->data_meta;
  struct t_meta *md = data_meta;
  if ((void *)(md + 1) > data) {
    bpf_printk("md + 1 > data\n");
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }

  __u16 lentot = 0;
  __u16 lens[4] = {bpf_ntohs(md->len1), bpf_ntohs(md->len2),
                   bpf_ntohs(md->len3), bpf_ntohs(md->len3)};

  // bpf_printk("valid: %d\n", bpf_ntohs(md->valid));
  // bpf_printk("lens: %d %d %d %d\n", lens[0], lens[1], lens[2], lens[3]);

  __u32 zero = 0;
  struct geosampling *geo = bpf_map_lookup_elem(&geosampling, &zero);

  if (!geo) {
    bpf_printk("geo is null\n");
    return XDP_DROP;
  }

  if (geo->count > HASHFN_N) {
    geo->count -= HASHFN_N;
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
  }

  __u32 row_to_update = geo->count;
  __u32 next_geo_value;

  struct countmin *cm = bpf_map_lookup_elem(&countmin, &zero);
  if (!cm)
    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);

  // int samplerate = 2;

  struct pkt_5tuple pkts[4] __attribute__((aligned(32))) = {0};
  __u16 pkts_hashes[4][4] = {0};

  int ret1 = handle_pkt(data, data_end, &pkts[0]);
  int ret2 = handle_pkt(data + (lens[0] & 0x1FFF), data_end, &pkts[1]);
  int ret3 =
      handle_pkt(data + ((lens[0] + lens[1]) & 0x1FFF), data_end, &pkts[2]);
  int ret4 = handle_pkt(data + ((lens[0] + lens[1] + lens[2]) & 0x1FFF), data_end,
                        &pkts[3]);
  if (ret1 || ret2 || ret3 || ret4) {
    // if (ret1 || ret2 || ret3){
    // if (ret1 || ret2){
    // bpf_printk("ret1: %d ret2: %d ret3: %d ret4:%d\n", ret1, ret2, ret3,
    // ret4);
    bpf_printk("ret1: %d ret2: %d\n", ret1, ret2);
    bpf_printk("handle_pkt failed\n");
    return ret1;
  }

  hash(pkts, pkts_hashes);

  nitro_update(cm, pkts_hashes[0], geo, row_to_update, next_geo_value);
  nitro_update(cm, pkts_hashes[1], geo, row_to_update, next_geo_value);
  nitro_update(cm, pkts_hashes[2], geo, row_to_update, next_geo_value);
  nitro_update(cm, pkts_hashes[3], geo, row_to_update, next_geo_value);

  return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
