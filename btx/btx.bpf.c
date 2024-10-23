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
	// 	// write a swap xdp program
	// 	void *data_end = (void *)(long)ctx->data_end;
	// 	void *data = (void *)(long)ctx->data;
	// 	void *data_meta = (void *)(long)ctx->data_meta;

	// 	struct t_meta *md = data_meta;
	// 	if (md + 1 > data)
	// 	{
	// 		return XDP_DROP + (XDP_DROP << 4);
	// 	}

	// 	struct ethhdr *eth = data;
	// 	if (eth + 1 > data_end)
	// 	{
	// 		return XDP_DROP + (XDP_DROP << 4);
	// 	}

	// 	struct ethhdr *eth2 = data + md->offset;
	// 	if (eth2 + 1 > data_end)
	// 	{
	// 		return XDP_DROP + (XDP_DROP << 4);
	// 	}

	// 	// swap mac address
	// 	__u64 src_mac = 0;
	// 	__builtin_memcpy(&src_mac, eth->h_source, ETH_ALEN);
	// 	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	// 	__builtin_memcpy(eth->h_dest, &src_mac, ETH_ALEN);

	// 	__builtin_memcpy(&src_mac, eth2->h_source, ETH_ALEN);
	// 	__builtin_memcpy(eth2->h_source, eth2->h_dest, ETH_ALEN);
	// 	__builtin_memcpy(eth2->h_dest, &src_mac, ETH_ALEN);
	return XDP_PASS + (XDP_TX << 4);
}

char __license[] SEC("license") = "GPL";
