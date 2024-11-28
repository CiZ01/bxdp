#include <arpa/inet.h>
#include <assert.h> 

#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <sys/resource.h>
#include "bnat.bpf.skel.h"

int if_index;
struct bnat_bpf *bnat;

struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};


void sig_handler(int sig)
{
	bpf_xdp_detach(if_index, 0, NULL);
	bnat_bpf__destroy(bnat);
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

void updatelpm() {
    __u64 counttot=0;

    struct ipv4_lpm_key key;

	__u32 newip = inet_addr("100.100.100.100");

    for(__u8 i=8; i<=32;i++){
        __u64 count=0;
        FILE *fp;
        char string[50];
        sprintf(string,"/home/vladimiro/bxdp/router/RCC25/%d.txt",i);
        fp = fopen(string, "r");
        char *line = NULL;
        size_t len = 0;
        ssize_t read;
        if (fp == NULL){
            printf("Map file not found\n");
            continue;
        }
        while ((read = getline(&line, &len, fp)) != -1) {
            line[strcspn(line,"\n")]=0;
            key.prefixlen = i;
            key.data = inet_addr(line);
            assert(bpf_map__update_elem(bnat->maps.lpm, &key,sizeof(struct ipv4_lpm_key), &newip,sizeof(newip), BPF_ANY)==0);
            count++;
            counttot++;
        }
        fclose(fp);
	    	if (line)
		free(line);
		// printf("Rules in map n %d = %llu Total number of rules = %llu\n",i,count,counttot);
    }
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

	bnat = bnat_bpf__open_and_load();

	if (!bnat)
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
	err = bpf_xdp_attach(if_index, bpf_program__fd(bnat->progs.bnat), 0, NULL);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF program\n");
		return 1;
	}
	updatelpm();
	printf("BPF program attached\n");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (1)
		;

	return 0;
}
