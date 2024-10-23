#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DEBUG 1

// struct pkt_5tuple
// {
// 	__be32 src_ip;
// 	__be32 dst_ip;
// 	__be16 src_port;
// 	__be16 dst_port;
// 	__u8 proto;

// } __attribute__((packed));

typedef struct s_meta
{
	// unsigned short len;
	unsigned short offset;
} t_meta;

__attribute__((__always_inline__)) static inline int packet_process(struct ethhdr *ethhdr, void *len)
{
	// if (ethhdr + 1 > len)
	// {
	// 	return XDP_PASS;
	// }
	return XDP_DROP;
}

SEC("xdp")
int bpass(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	void *md = (void *)(long)ctx->data_meta;

	if (md + 2 > data)
	{
#if DEBUG
		bpf_printk("metadata %p %p", md, data);
		bpf_printk("metadata too big\n");
#endif
		return XDP_DROP + (XDP_DROP << 4);
	}
	t_meta *meta = md;
#if DEBUG
	bpf_printk("metadata: %x", bpf_ntohs(meta->offset));
#endif

	struct ethhdr *eth1 = data;
	if (data + 1 > data_end)
	{
#if DEBUG
		bpf_printk("eth1 header too big\n");
#endif
		return XDP_DROP + (XDP_DROP << 4);
	}
	bpf_printk("first value eth1: %x", eth1->h_dest[0]);
	/*
if (data + meta->offset > data_end) {
	#if DEBUG
		bpf_printk("eth2 offset too big\n");
	#endif
	return XDP_PASS + (XDP_DROP << 4);
}*/
	struct ethhdr *eth2 = md + (bpf_ntohs(meta->offset) & 0x0F);

	if (eth2 + 1 > data_end)
	{
#if DEBUG
		// bpf_printk("data_end=%p |||| eth2=%p\n", data_end, eth2);
		// bpf_printk("md+meta offset=%p |||| md + metaoffset + sizeof = %p\n", md + meta->offset, eth2 + 1);
		bpf_printk("eth2 header too big\n");
#endif
		return XDP_PASS + (XDP_DROP << 4);
	}

	int r1 = packet_process(eth1, eth1 + meta->offset);
	int r2 = packet_process(eth2, data_end);

	// __u64 nh_off = 0;
	// nh_off = sizeof(*eth1);
	// struct iphdr *ip = data + nh_off;
	// struct pkt_5tuple pkt;

	return r1 + (r2 << 4);
	// return XDP_PASS + (XDP_PASS << 4);
}

char __license[] SEC("license") = "GPL";
