#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


SEC("xdp")
int tx(struct xdp_md *ctx)
{
	return XDP_TX;
}

char __license[] SEC("license") = "GPL";
