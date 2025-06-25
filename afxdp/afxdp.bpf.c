/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp")
int afxdp(struct xdp_md *ctx)
{
	int index = ctx->rx_queue_index;

	if (bpf_map_lookup_elem(&xsks_map, &index))
		return bpf_redirect_map(&xsks_map, index, XDP_DROP);

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";