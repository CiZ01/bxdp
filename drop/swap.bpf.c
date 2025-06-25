#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <string.h>


SEC("xdp")
int swap(struct xdp_md *ctx)
{

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
	{
		return XDP_DROP;
	}

	//swap the source and destination MAC addresses
	__be16 tmp[ETH_ALEN];
	memcpy(tmp, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source,eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, tmp, ETH_ALEN);

	return XDP_DROP;
}

char __license[] SEC("license") = "GPL";
