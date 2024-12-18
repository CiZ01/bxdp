#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int bdrop(struct xdp_md *ctx)
{
return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
	//return XDP_PASS + (XDP_PASS << 4) + (XDP_PASS << 8) + (XDP_PASS << 12);
}

char __license[] SEC("license") = "GPL";
