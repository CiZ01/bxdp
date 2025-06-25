#include "redirect.bpf.skel.h"
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <sys/resource.h>

#define ETH_ALEN 6

int if_index;
struct redirect_bpf *redirect;

void sig_handler(int sig) {
  bpf_xdp_detach(if_index, 0, NULL);
  redirect_bpf__destroy(redirect);
  exit(0);
}

void bump_memlock_rlimit(void) {
  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    exit(1);
  }
}
int main(int argc, char **argv) {

  int err;
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
    return 1;
  }

  bump_memlock_rlimit();

  redirect = redirect_bpf__open_and_load();

  if (!redirect) {
    fprintf(stderr, "Failed to open and load BPF object\n");
    return 1;
  }

  if_index = if_nametoindex(argv[1]);
  if (!if_index) {
    fprintf(stderr, "Failed to get ifindex of %s\n", argv[1]);
    return 1;
  }

  // setting  rx_port maps
  int redirect_ifindex = if_nametoindex("enp52s0f0np0");
  if (!redirect_ifindex) {
    fprintf(stderr, "Failed to get ifindex of %s\n", "enp52s0f1np0");
    return 1;
  }

  int key = 0;
  err = bpf_map__update_elem(redirect->maps.tx_port, &key, sizeof(key),
                             &redirect_ifindex, sizeof(redirect_ifindex), 0);
  unsigned char src[ETH_ALEN] = {0x58, 0xa2, 0xe1, 0xd0, 0x69, 0xcf};
  unsigned char dst[ETH_ALEN] = {0x58, 0xa2, 0xe1, 0xd0, 0x69, 0xce};
  
  // setting params map
  err = bpf_map__update_elem(redirect->maps.redirect_params, src, sizeof(src),
                             dst, sizeof(dst), 0);
  if (err) {
    fprintf(stderr, "Failed to update redirect_params map\n");
    return 1;
  }

  err = bpf_xdp_attach(if_index, bpf_program__fd(redirect->progs.redirect), 0,
                       NULL);
  if (err) {
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
