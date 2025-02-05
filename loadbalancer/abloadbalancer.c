#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <sys/resource.h>
#include "abloadbalancer.bpf.skel.h"
#include "common.h"

int if_index;
struct abloadbalancer_bpf *abloadbalancer;

void sig_handler(int sig)
{
	bpf_xdp_detach(if_index, 0, NULL);
	abloadbalancer_bpf__destroy(abloadbalancer);
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

int fill_map(struct bpf_map *map, char *filename)
{
	// FILE *file = fopen(filename, "r");
  	// if (!file) {
    // 	return 1;
    // 	fprintf(stderr, "Failed to open file\n");
  	// }

	struct dest_info tnl;
	char saddr[] = "10.10.10.10";
	tnl.saddr = inet_addr(saddr);
	char daddr[] = "10.10.10.10";
	tnl.daddr = inet_addr(daddr);
	char dmac[] = "00:15:4d:d4:46:8f";
	sscanf(dmac, "%hx:%hx:%hx:%hx:%hx:%hx", &tnl.dmac[0], &tnl.dmac[1], &tnl.dmac[2], &tnl.dmac[3], &tnl.dmac[4], &tnl.dmac[5]);
	
	__u64 key = 0;
	int err = bpf_map__update_elem(map, &key,sizeof(key), &tnl,sizeof(tnl), BPF_ANY);
	if (err) {
      fprintf(stderr, "Failed to update map: %s\n", strerror(-err));
      return err;
    }

	FILE *file = fopen(filename, "r");
	if (!file) {
		fprintf(stderr, "Failed to open file\n");
		return 1;
	}

	char *line;
	size_t len = 0;
	size_t read;
	__u64 n = 0;
	const char delimiter[] = ",";
    char *token;
	while ((read = getline(&line,&len, file))!= -1){
		// line[strcspn(line,"\n")]=0;
		token = strtok(line, delimiter);

		while (token != NULL){
			tnl.saddr = inet_addr(token);
			token = strtok(NULL, delimiter);
			sscanf(token, "%hx:%hx:%hx:%hx:%hx:%hx", &tnl.dmac[0], &tnl.dmac[1], &tnl.dmac[2], &tnl.dmac[3], &tnl.dmac[4], &tnl.dmac[5]);
			token = strtok(NULL, delimiter);
			err = bpf_map__update_elem(map, &n,sizeof(n), &tnl,sizeof(tnl), BPF_ANY);
			if (err) {
				fprintf(stderr, "Failed to update map: %s\n", strerror(-err));
				return err;
			}
			// printf("n: %d, saddr: %u, daddr: %u, dmac: %x:%x:%x:%x:%x:%x\n", n, tnl.saddr, tnl.daddr, tnl.dmac[0], tnl.dmac[1], tnl.dmac[2], tnl.dmac[3], tnl.dmac[4], tnl.dmac[5]);
		}
		n++;
		key = n % MAX_DEST;
		int err = bpf_map__update_elem(map, &key,sizeof(key), &tnl,sizeof(tnl), BPF_ANY);
		if (err) {
			fprintf(stderr, "Failed to update map: %s\n", strerror(-err));
		return err;
    	}
	}

	fclose(file);
	if (line)
		free(line);
	return 0;

}
int main(int argc, char **argv)
{

	int err;
	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s <ifname> <file_map_ips>\n", argv[0]);
		return 1;
	}

	bump_memlock_rlimit();

	abloadbalancer = abloadbalancer_bpf__open();//_and_load();


	if (!abloadbalancer)
	{
		fprintf(stderr, "Failed to open BPF object\n");
		return 1;
	}

	if_index = if_nametoindex(argv[1]);
	if (!if_index)
	{
		fprintf(stderr, "Failed to get ifindex of %s\n", argv[1]);
		return 1;
	}

	err = abloadbalancer_bpf__load(abloadbalancer);
	if (err)
	{
		fprintf(stderr, "Failed to load BPF object\n");
		return 1;
	}

	err = fill_map(abloadbalancer->maps.servers, argv[2]);


	err = bpf_xdp_attach(if_index, bpf_program__fd(abloadbalancer->progs.abloadbalancer), 0, NULL);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF program\n");
		return 1;
	}
	printf("BPF program attached\n");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (1)
		;

	return 0;
}
