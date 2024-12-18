// This macro is required to include <immintrin.h> in the kernel
#ifdef __clang__
#define __MM_MALLOC_H
#else
#define _MM_MALLOC_H_INCLUDED
#endif

#include <immintrin.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <x86intrin.h>

#include "../common.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Author");
MODULE_DESCRIPTION("SIMD ACL");

static __m512i_u vec1;

__bpf_kfunc int cmp_512_128_simd(const struct pkt5 *arr2);
__bpf_kfunc void load_mm512i(const struct pkt5 *p);

static __m512i __from_128_to_512(__m128i vec128) {

  __m256i vec256 = _mm256_broadcastsi128_si256(vec128);
  __m512i vec512 = _mm512_castsi256_si512(vec256);
  vec512 = _mm512_inserti64x4(vec512, vec256, 1);

  return vec512;
}

__bpf_kfunc void load_mm512i(const struct pkt5 *p) {
  vec1 = _mm512_loadu_si512((__m512i_u *)p);
}

__bpf_kfunc int cmp_512_128_simd(const struct pkt5 *pkt5) {
  const __m128i_u *p2 = (__m128i_u *)pkt5;

  __m512i vec2 = __from_128_to_512(_mm_loadu_si128(p2));
  __m512i diff = _mm512_xor_si512(vec1, vec2);
  __mmask8 res = _mm512_test_epi64_mask(diff, diff);

  return !res;
}

BTF_SET8_START(bpf_task_set)
BTF_ID_FLAGS(func, cmp_512_128_simd)
BTF_ID_FLAGS(func, load_mm512i)
BTF_SET8_END(bpf_task_set)

static const struct btf_kfunc_id_set bpf_task_kfunc_set = {
    .owner = THIS_MODULE,
    .set = &bpf_task_set,
};

static int __init ebpf_avx_init(void) {
  register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_task_kfunc_set);
  pr_info("eBPF AVX module loaded\n");
  return 0;
}

static void __exit ebpf_avx_exit(void) {
  pr_info("eBPF AVX module unloaded\n");
}
module_init(ebpf_avx_init);
module_exit(ebpf_avx_exit);