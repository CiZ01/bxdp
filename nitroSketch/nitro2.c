#include "nitro2.bpf.skel.h"
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>

#include <gsl/gsl_randist.h>
#include <gsl/gsl_rng.h>

int if_index;
struct nitro2_bpf *nitro2;

void sig_handler(int sig) {
  bpf_xdp_detach(if_index, 0, NULL);
  nitro2_bpf__destroy(nitro2);
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

struct geosampling {
  __u32 geo_sampling_array[4096];
  __u32 geo_sampling_idx;
  __u32 count;
};

int fill_geo(struct bpf_map *map) {
  struct geosampling gs = {
      .geo_sampling_array = {0},
      .geo_sampling_idx = 0,
      .count = 0,
  };

  const gsl_rng_type *T;
  gsl_rng *r;

  gsl_rng_env_setup();
  T = gsl_rng_default;
  r = gsl_rng_alloc(T);

  gsl_rng_set(r, 42);

  for (int i = 0; i < 4096; i++) { // samplig rate
    gs.geo_sampling_array[i] = gsl_ran_geometric(r, 0.006);
    // printf("gs.geo_sampling_array[%d] = %d\n", i, gs.geo_sampling_array[i]);
  }

//   struct geosampling gs_cpu[libbpf_num_possible_cpus()];
//   for (int i = 0; i < libbpf_num_possible_cpus(); i++) {
//     memcpy(&gs_cpu[i], &gs, sizeof(gs));
//   }

  int key = 0;
  int ret =
    //   bpf_map__update_elem(map, &key, sizeof(key), &gs_cpu,
    //                        sizeof(gs) * libbpf_num_possible_cpus(), BPF_ANY);
		bpf_map__update_elem(map, &key, sizeof(key), &gs,
                           sizeof(gs), BPF_ANY);
  if (ret) {
    fprintf(stderr, "Failed to update geo map\n");
    return ret;
  }

  gsl_rng_free(r);

  return 0;
}

int main(int argc, char **argv) {

  int err;
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
    return 1;
  }

  bump_memlock_rlimit();

  nitro2 = nitro2_bpf__open_and_load();

  if (!nitro2) {
    fprintf(stderr, "Failed to open and load BPF object\n");
    return 1;
  }

  err = fill_geo(nitro2->maps.geosampling);
  if (err) {
    fprintf(stderr, "Failed to fill external map\n");
    return 1;
  }

  if_index = if_nametoindex(argv[1]);
  if (!if_index) {
    fprintf(stderr, "Failed to get ifindex of %s\n", argv[1]);
    return 1;
  }
  err =
      bpf_xdp_attach(if_index, bpf_program__fd(nitro2->progs.nitro2), 0, NULL);
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
