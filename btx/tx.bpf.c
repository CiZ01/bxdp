#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


SEC("xdp")
int tx(struct xdp_md *ctx)
{
	return XDP_TX;
}

char __license[] SEC("license") = "GPL";
