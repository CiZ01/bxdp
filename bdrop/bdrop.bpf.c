#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int bdrop(struct xdp_md *ctx)
{
	return XDP_DROP + (XDP_DROP << 4);
}

char __license[] SEC("license") = "GPL";
