#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct t_meta
{
	__u16 offset;
};

SEC("xdp")
int btx(struct xdp_md *ctx)
{
	return XDP_TX + (XDP_TX << 4);
}

char __license[] SEC("license") = "GPL";
