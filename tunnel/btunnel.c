#include <arpa/inet.h>
#include <assert.h> 

#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <sys/resource.h>
#include "btunnel.bpf.skel.h"
#include "tunnel_common.h"

int if_index;
struct btunnel_bpf *btunnel;

void sig_handler(int sig)
{
	bpf_xdp_detach(if_index, 0, NULL);
	btunnel_bpf__destroy(btunnel);
	exit(0);
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
	{
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
	if (setrlimit(RLIMIT_STACK, &rlim_new))
	{
		fprintf(stderr, "Failed to increase RLIMIT_STACK limit!\n");
		exit(1);
	}
	if (setrlimit(RLIMIT_DATA, &rlim_new))
	{
		fprintf(stderr, "Failed to increase RLIMIT_DATA limit!\n");
		exit(1);
	}
	if (setrlimit(RLIMIT_AS, &rlim_new))
	{
		fprintf(stderr, "Failed to increase RLIMIT_AS limit!\n");
		exit(1);
	}
}

void updatemap(){

    struct vip vip;
    // vip.family = AF_INET;
    vip.family = 2;
    // vip.protocol = IPPROTO_UDP;
    vip.protocol = 17;

    vip.dport=3072;
    // vip.daddr.v4=inet_addr("16.0.0.1");
    vip.daddr.v4=16777264;


    struct iptnl_info tnl;
    tnl.saddr.v4 = inet_addr("10.10.1.2");
    tnl.daddr.v4 = inet_addr("10.10.1.1");

    tnl.family = AF_INET;
    tnl.dmac[0] = 0x00;
    tnl.dmac[1] = 0x00;
    tnl.dmac[2] = 0x00;
    tnl.dmac[3] = 0x00;
    tnl.dmac[4] = 0x00;
    tnl.dmac[5] = 0x00;


    __u8 key = 0;
    
    assert(bpf_map__update_elem(btunnel->maps.vip2tnl, &key ,sizeof(__u8), &tnl,sizeof(struct iptnl_info), BPF_ANY)==0);

}

int main(int argc, char **argv)
{

	int err;
	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
		return 1;
	}

	bump_memlock_rlimit();

	btunnel = btunnel_bpf__open_and_load();

	if (!btunnel)
	{
		fprintf(stderr, "Failed to open and load BPF object\n");
		return 1;
	}

	if_index = if_nametoindex(argv[1]);
	if (!if_index)
	{
		fprintf(stderr, "Failed to get ifindex of %s\n", argv[1]);
		return 1;
	}
	err = bpf_xdp_attach(if_index, bpf_program__fd(btunnel->progs.btunnel), 0, NULL);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF program\n");
		return 1;
	}
	updatemap();
	printf("BPF program attached\n");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (1)
		;

	return 0;
}