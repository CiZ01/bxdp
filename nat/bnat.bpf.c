#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>

struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};

struct t_meta
{
    unsigned short valid;
    unsigned short len1;
    unsigned short len2;
    unsigned short len3;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1000000);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);

} lpm SEC(".maps") ;

static __always_inline int handle_pkt(void *data, void *data_end, struct ipv4_lpm_key *pkt)
{
    struct ethhdr *eth = data;
    if (eth + 1 >= data_end)
        return -1;

    __u16 h_proto = eth->h_proto;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 >= data_end)
        return -1;
    pkt->data = ip->saddr;
    pkt->prefixlen = 32;
    // bpf_printk("pre src_ip: %pI4\n", &pkt->data);

    return 0;
}


static __always_inline __u16 csum_fold_helper(__u64 csum)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16 iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}


static __always_inline int update_ipaddr(void *data, void *data_end, __u32 newip)
{
    struct ethhdr *eth = data;
    if (eth + 1 >= data_end)
        return -1;

    __u16 h_proto = eth->h_proto;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 >= data_end)
        return -1;
    ip->saddr = newip;
    ip->check = iph_csum(ip);

    // bpf_printk("post src_ip: %pI4\n", &ip->saddr);

    return 0;
}





SEC("xdp")
int bnat(struct xdp_md *ctx) {
    void* data = (void*)(long)(ctx->data);
    void* data_end = (void*)(long)(ctx->data_end);
    void *data_meta = (void *)(long)ctx->data_meta;
    struct t_meta *md = data_meta;
    if (md + 1 > data)
    {
        return XDP_DROP + (XDP_DROP << 4) + (XDP_DROP << 8) + (XDP_DROP << 12);
    }

    __u16 lens[4] = {bpf_ntohs(md->len1), bpf_ntohs(md->len2), bpf_ntohs(md->len3), bpf_ntohs(md->len3)};
    __u16 lentot = 0;

    for( int i = 0; i < 4; i++ ) {
        if(bpf_ntohs(md->valid) & (1 << i)) {
            struct ipv4_lpm_key key;

            int ret = handle_pkt(data+(lentot &0xFF), data_end, &key);
            if (ret)
                return ret;

            __u32 *value = bpf_map_lookup_elem(&lpm, &key);

            

            if(value){
                // bpf_printk("Matched pkt 1 with rule %u\n",value[0]);
                // bpf_printk("Matched pkt %d\n with rule %d\n", i,value[0]);

                update_ipaddr(data+(lentot &0xFF), data_end, *value);
                // return XDP_DROP;
                // goto end;
            }else{
                // bpf_printk("Not Matched pkt %d\n", i);
                // goto end;
            }


            lentot += lens[i];
        }
    }
    
end:
    return XDP_TX + (XDP_TX << 4) + (XDP_TX << 8) + (XDP_TX << 12);
};


char LICENSE[] SEC("license") = "Dual BSD/GPL";
