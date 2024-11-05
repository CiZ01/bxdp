#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct t_meta
{
    // unsigned short len;
    unsigned short offset;
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 2);
} my_map SEC(".maps");

SEC("xdp")
int bmap(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    void *md = (void *)(long)ctx->data_meta;
    if (md + 2 > data)
    {
        bpf_printk("metadata %p %p", md, data);
        return XDP_DROP + (XDP_DROP << 4);
    }

    struct t_meta *md_offset = md;
    __u8 offset = bpf_ntohs(md_offset->offset) & 0xFF;

    struct ethhdr *eth = data;
    if (eth + 1 > data_end || eth + 1 > data + offset)
    {
        bpf_printk("eth1 header too big\n");
        return XDP_DROP + (XDP_DROP << 4);
    }

    __u32 key = 0;
    __u8 *value = bpf_map_lookup_elem(&my_map, &key);
    if (value)
        *value = eth->h_proto;

    struct ethhdr *eth2 = data + (bpf_ntohs(md_offset->offset) & 0x0FF);
    if (eth2 + 1 > data_end)
    {
        bpf_printk("eth2 header too big\n");
        return XDP_DROP + (XDP_DROP << 4);
    }

    __u32 key2 = 1;

    __u8 *value2 = bpf_map_lookup_elem(&my_map, &key2);
    if (value2)
        *value2 = eth2->h_proto;

    return XDP_DROP + (XDP_PASS << 4);
}

char __license[] SEC("license") = "GPL";
