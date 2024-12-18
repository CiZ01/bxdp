#include <linux/ip.h>

#define MAX_ENTRIES 100000

struct pkt5 {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  __u32 proto; // 32 bits are needed to avoid padding in the struct, should be 8 bits
};
