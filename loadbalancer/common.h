#include <linux/if_ether.h>
#include <linux/ip.h>

#define MAX_DEST 512
#define MAX_SERVERS 512
#define _SEED_HASHFN 77

struct dest_info {
	__u32 saddr;
	__u32 daddr;
	// __u64 pkts;
	__be16 dmac[ETH_ALEN];
};