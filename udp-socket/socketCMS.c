#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include "xxhash64.h"
#include <signal.h>


// #define BUFFER_SIZE 65536
#define BUFFER_SIZE 1500

#define HASHFN_N 4
#define COLUMNS 1048576
#define _SEED_HASHFN 77


struct pkt_5tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    uint8_t proto;
} __attribute__((packed));

struct countmin {
    __u64 values[HASHFN_N][COLUMNS];
};

void print_ip(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    printf("%s", inet_ntoa(addr));
}

static __always_inline void hash(const void *pkt, const __u64 len, __u16 hashes[4])
{
    __u64 h = xxhash64(pkt, len, _SEED_HASHFN);
    hashes[0] = (h & 0xFFFF);
    hashes[1] = h >> 16 & 0xFFFF;
    hashes[2] = h >> 32 & 0xFFFF;
    hashes[3] = h >> 48 & 0xFFFF;
    return;
}

static __always_inline void countmin_add(struct countmin *cm, const __u16 hashes[4])
{
    for (int i = 0; i < HASHFN_N; i++)
    {
        __u32 target_idx = hashes[i] & (COLUMNS - 1);
        cm->values[i][target_idx]++;
    }
    return;
}





struct countmin cm;
int sockfd;
time_t last_time;
int packet_count = 0;

void sig_handler(int sig)
{
    // printf("CountMin Sketch:\n");
    // for (int i = 0; i < HASHFN_N; i++) {
    //     printf("  Hash %d: ", i);
    //     for (int j = 0; j < COLUMNS; j++) {
    //         if(cm.values[i][j] > 0){
    //             printf("%llu ", cm.values[i][j]);
    //         }
    //     }
    //     printf("\n");
    // }
    printf("\n");
    close(sockfd);
	exit(0);
}


int main(int argc, char **argv) {
    char buffer[BUFFER_SIZE];

    if (argc < 2)
	{
		fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
		return 1;
	}
    

    // Creazione socket raw
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    // Bind a una interfaccia specifica
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL); // prendi tutto
    sll.sll_ifindex = if_nametoindex(argv[1]);

    if (sll.sll_ifindex == 0) {
        perror("if_nametoindex: interfaccia non trovata");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (bind(sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("In ascolto su %s...\n", argv[1]);
    signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

    while (1) {
        ssize_t len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (len < 0) {
            perror("recvfrom");
            break;
        }

        // Header Ethernet
        struct ethhdr *eth = (struct ethhdr *)buffer;

        // Controlla se è IPv4
        if (ntohs(eth->h_proto) != ETH_P_IP)
            continue;

        // Header IP
        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        if (ip->protocol != IPPROTO_UDP)
            continue;

        // Header UDP
        struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);

        struct pkt_5tuple pkt;
        pkt.src_ip = ip->saddr;
        pkt.dst_ip = ip->daddr;
        pkt.src_port = udp->source;
        pkt.dst_port = udp->dest;
        pkt.proto = ip->protocol;
        __u16 hashes[HASHFN_N];
        hash(&pkt, sizeof(pkt), hashes);
        countmin_add(&cm, hashes);

        packet_count++;

        time_t now = time(NULL);
        if (now > last_time) {
            printf("PPS: %d\n", packet_count);
            packet_count = 0;
            last_time = now;
        }

    }

    return 0;
}
