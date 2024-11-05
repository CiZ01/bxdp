#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int  drop(struct xdp_md *ctx)
{
	return XDP_DROP;
}

char __license[] SEC("license") = "GPL";
