#include "common.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "bacl.bpf.skel.h"
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <signal.h>
#include <sys/resource.h>

int if_index;
struct bacl_bpf *bacl;

int mask = 1;

void sig_handler(int sig) {
  bpf_xdp_detach(if_index, 0, NULL);
  bacl_bpf__destroy(bacl);
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
  if (setrlimit(RLIMIT_STACK, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_STACK limit!\n");
    exit(1);
  }
  if (setrlimit(RLIMIT_DATA, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_DATA limit!\n");
    exit(1);
  }
  if (setrlimit(RLIMIT_AS, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_AS limit!\n");
    exit(1);
  }
}

__be32 ip_mask(const char *ip_str, __u32 prefix_length) {

  uint32_t ip, masked_ip;

  // if (sscanf(ip_with_mask, "%15[^/]/%d", ip_str, &prefix_length) != 2) {
  //   fprintf(stderr, "Formato IP/Mascheramento non valido\n");
  //   return 0;
  // }

  if (inet_pton(AF_INET, ip_str, &ip) != 1) {
    fprintf(stderr, "Indirizzo IP non valido\n");
    return 0;
  }

  if (!prefix_length)
    return ip;

  uint32_t mask =
      (prefix_length == 0) ? 0 : (0xFFFFFFFF << (32 - prefix_length));
  masked_ip = ip & mask;

  return masked_ip;
}

int set_max_entries(struct bpf_map *map, char *filename) {
  FILE *file = fopen(filename, "r");

  // get number of lines
  unsigned int max_entr = 0;
  char ch;
  while (!feof(file)) {
    ch = fgetc(file);
    if (ch == '\n') {
      max_entr++;
    }
  }
  fclose(file);
  int err = bpf_map__set_max_entries(map, max_entr + 1);
  if (err) {
    fprintf(stderr, "Failed to set max entries: %s\n", strerror(-err));
    return 1;
  }

  return 0;
}

int fill_tbl(struct bpf_map *map, char *filename) {
  FILE *file = fopen(filename, "r");
  if (!file) {
    return 1;
    fprintf(stderr, "Failed to open file\n");
  }

  char *line;
  size_t len = 0;
  size_t read;
  uint32_t n = 0;
  struct pkt5 rule = {0};
  char *tok;

  int n_mask = 0;
  while ((read = getline(&line, &len, file)) != -1) {
    if (mask)
      n_mask = n % 32;
    tok = strtok(line, " ");
    rule.src_ip = ip_mask(tok, n_mask);
    rule.dst_ip = ip_mask(strtok(NULL, " "), n_mask);
    rule.src_port = atoi(strtok(NULL, " "));
    rule.dst_port = atoi(strtok(NULL, " "));
    rule.proto = atoi(strtok(NULL, " "));

    int err = bpf_map__update_elem(map, &n, sizeof(uint32_t), &rule,
                                   sizeof(struct pkt5), BPF_ANY);
    if (err) {
      fprintf(stderr, "Failed to update map: %s\n", strerror(-err));
      return err;
    }
    n++;
  }

  fclose(file);

  return 0;
}

int main(int argc, char **argv) {

  int err;
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <ifname> <file_tbl>\n", argv[0]);
    return 1;
  }

  if (argc == 3) {
    mask = atoi(argv[2]);
  }

  bump_memlock_rlimit();

  bacl = bacl_bpf__open();
  if (!bacl) {
    fprintf(stderr, "Failed to open BPF object\n");
    return 1;
  }

  if_index = if_nametoindex(argv[1]);
  if (!if_index) {
    fprintf(stderr, "Failed to get ifindex of %s\n", argv[1]);
    return 1;
  }

  err = set_max_entries(bacl->maps.rule_tbl, argv[2]);
  if (err) {
    fprintf(stderr, "Failed to set max entries\n");
    return 1;
  }

  err = bacl_bpf__load(bacl);
  if (err) {
    fprintf(stderr, "Failed to load BPF object\n");
    return 1;
  }
  err = fill_tbl(bacl->maps.rule_tbl, argv[2]);
  if (err) {
    fprintf(stderr, "Failed to fill external map\n");
    return 1;
  }

  err = bpf_xdp_attach(if_index, bpf_program__fd(bacl->progs.bacl), 0, NULL);
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
