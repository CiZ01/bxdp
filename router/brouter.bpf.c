#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
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
    // unsigned short len;
    unsigned short offset;
};


struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1000000);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
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
    return 0;
}

SEC("xdp")
int brouter(struct xdp_md *ctx) {
    void* data = (void*)(long)(ctx->data);
    void* data_end = (void*)(long)(ctx->data_end);
    void *data_meta = (void *)(long)ctx->data_meta;
    struct t_meta *md = data_meta;
    if (md + 1 > data)
    {
        return XDP_DROP + (XDP_DROP << 4);
    }
    
    //pkt 1
    struct ipv4_lpm_key key1;
    int ret =  handle_pkt(data, data_end, &key1);
    if (ret < 0){
        // bpf_printk("Error parsing packet 1\n");
        return XDP_DROP + (XDP_DROP << 4);
    }
    __u8 *value = bpf_map_lookup_elem(&lpm, &key1);

    if(value){
        // bpf_printk("Matched pkt 1 with rule %u\n",value[0]);
        // return XDP_DROP;
        // goto end;
    }else{
        // bpf_printk("Not Matched pkt 1\n");
        // return XDP_DROP;
        // goto end;
    }

    //pkt 2
    struct ipv4_lpm_key key2;
    ret =  handle_pkt(data + (bpf_ntohs(md->offset) & 0xFF), data_end, &key2);
    if (ret < 0){
        // bpf_printk("Error parsing packet 2\n");
        return XDP_DROP + (XDP_DROP << 4);
    }
    value = bpf_map_lookup_elem(&lpm, &key2);

    if(value){
        // bpf_printk("Matched pkt 2 with rule %u\n",value[0]);
        // return XDP_DROP;
        // goto end;
    }else{
        // bpf_printk("Not Matched pkt 2\n");
        // return XDP_DROP;
        // goto end;
    }


end:
    return XDP_DROP + (XDP_DROP << 4);
};


char LICENSE[] SEC("license") = "Dual BSD/GPL";