#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct t_meta {
  unsigned short valid;
  unsigned short len1;
  unsigned short len2;
  unsigned short len3;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, __be32);
    __type(value, __u64);
} ips SEC(".maps");


static __always_inline __be32 get_ip(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    if (eth + 1 > data_end)
        return -1;

    __u16 h_proto = eth->h_proto;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 > data_end)
        return -1;

    return ip->saddr;
}





SEC("xdp")
int obsampler(struct xdp_md *ctx) {



    void *data = (void *)(long)(ctx->data);
    void *data_end = (void *)(long)(ctx->data_end);
    void *data_meta = (void *)(long)ctx->data_meta;
    struct t_meta *md = data_meta;
    if ((void *)(md + 1) > data) {
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }

    __u16 lens[4] = {bpf_ntohs(md->len1), bpf_ntohs(md->len2),bpf_ntohs(md->len3), bpf_ntohs(md->len3)};

    __u8 randoms[4];
    __u32 random = bpf_get_prandom_u32();

    randoms[0] = (random & 0xFF);
    randoms[1] = random >> 8 & 0xFF;
    randoms[2] = random >> 16 & 0xFF;
    randoms[3] = random >> 24 & 0xFF;
    
    __be32 ip1=0;
    __be32 ip2=0;
    __be32 ip3=0;
    __be32 ip4=0;

    int samplerate = 1;

    if ((randoms[0] & ((1 << samplerate)-1)) == 0){
    ip1 = get_ip(data, data_end);
    }
    if ((randoms[1] & ((1 << samplerate)-1)) == 0){
    ip2 = get_ip(data + (lens[0] & 0xFF), data_end);
    }
    if ((randoms[2] & ((1 << samplerate)-1)) == 0){
    ip3 = get_ip(data + (lens[0] +lens[1] & 0xFF), data_end);
    }
    if ((randoms[3] & ((1 << samplerate)-1)) == 0){
    ip4 = get_ip(data + (lens[0] +lens[1] +lens[2] & 0xFF), data_end);
    }

    if (ip1 <= 0 || ip2 <= 0 || ip3 <= 0 || ip4 <= 0) {
    // if (ip1 < 0 || ip2 < 0 || ip3 < 0) {
    // if (ip1 < 0 || ip2 < 0) {
        bpf_printk("Failed to get ip1 %u ip2 %u ip3 %u ip4 %u\n", ip1, ip2, ip3, ip4);
        // return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }

    __u64 *count1=0;
    __u64 *count2=0;
    __u64 *count3=0;
    __u64 *count4=0;

    if ((randoms[0] & ((1 << samplerate)-1)) == 0 && ip1) {
        bpf_printk("ip1 %u\n", ip1);
        count1 = bpf_map_lookup_elem(&ips, &ip1);
    }

    if ((randoms[1] & ((1 << samplerate)-1)) == 0 && ip2) {
        bpf_printk("ip2 %u\n", ip2);
        count2 = bpf_map_lookup_elem(&ips, &ip2);
    }

    if ((randoms[2] & ((1 << samplerate)-1)) == 0 && ip3) {
        bpf_printk("ip3 %u\n", ip3);
        count3 = bpf_map_lookup_elem(&ips, &ip3);
    }

    if ((randoms[3] & ((1 << samplerate)-1)) == 0 && ip4) {
        bpf_printk("ip4 %u\n", ip4);
        count4 = bpf_map_lookup_elem(&ips, &ip4);
    }


    if ((randoms[0] & ((1 << samplerate)-1)) == 0 && ip1 && count1) {
        bpf_printk("count1 %u\n", *count1);
        *count1 += 1;
    } else if ((randoms[0] & ((1 << samplerate)-1)) == 0 && ip1 && !count1) {
        __u64 init = 1;
        bpf_map_update_elem(&ips, &ip1, &init, BPF_NOEXIST);
    }

    if ((randoms[1] & ((1 << samplerate)-1)) == 0 && ip2 && count2) {
        bpf_printk("count2 %u\n", *count2);
        *count2 += 1;
    } else if ((randoms[1] & ((1 << samplerate)-1)) == 0 && ip2 && !count2) {
        __u64 init = 1;
        bpf_map_update_elem(&ips, &ip2, &init, BPF_NOEXIST);
    }

    if ((randoms[2] & ((1 << samplerate)-1)) == 0 && ip3 && count3) {
        bpf_printk("count3 %u\n", *count3);
        *count3 += 1;
    } else if ((randoms[2] & ((1 << samplerate)-1)) == 0 && ip3 && !count3) {
        __u64 init = 1;
        bpf_map_update_elem(&ips, &ip3, &init, BPF_NOEXIST);
    }

    if ((randoms[3] & ((1 << samplerate)-1)) == 0 && ip4 && count4) {
        bpf_printk("count4 %u\n", *count4);
        *count4 += 1;
    } else if ((randoms[3] & ((1 << samplerate)-1)) == 0 && ip4 && !count4) {
        __u64 init = 1;
        bpf_map_update_elem(&ips, &ip4, &init, BPF_NOEXIST);
    }

    return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);

};


char LICENSE[] SEC("license") = "Dual BSD/GPL";
