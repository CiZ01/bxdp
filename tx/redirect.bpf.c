/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <string.h>

struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, 256);
} tx_port SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, unsigned char[ETH_ALEN]);
  __type(value, unsigned char[ETH_ALEN]);
  __uint(max_entries, 1);
} redirect_params SEC(".maps");

SEC("xdp")
int redirect(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  int action = XDP_DROP;
  unsigned char *dst;

  struct ethhdr *eth = data;
  if (data + sizeof(*eth) > data_end)
    return XDP_DROP;

  struct iphdr *ip = data + sizeof(*eth);
  if (data + sizeof(*ip) > data_end)
    return XDP_DROP;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_DROP;

  dst = bpf_map_lookup_elem(&redirect_params, eth->h_source);
  if (!dst)
    goto out;

  /* Set a proper destination address */
  memcpy(eth->h_dest, dst, ETH_ALEN);
  action = bpf_redirect_map(&tx_port, 0, 0);

out:
  return action;
}

char _license[] SEC("license") = "GPL";
