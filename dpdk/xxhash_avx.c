#include "xxhash_avx.h"


#define GET_FIST_32BIT(x) ((x) & 0xFFFFFFFF)

#define PRIME32_1 0x9E3779B1
#define PRIME32_2 0x85EBCA77
#define PRIME32_3 0xC2B2AE3D
#define PRIME32_4 0x27D4EB2F
#define PRIME32_5 0x165667B1


__m512i round_all16x4(__m512i accs, __m512i data,
                             const __m512i prime1_vec) {
  for (int i = 0; i < 4; i++) {
    accs = _mm512_add_epi64(accs, _mm512_mullo_epi64(data, prime1_vec));
    accs = _mm512_rol_epi64(accs, 17);
    accs = _mm512_mullo_epi64(accs, prime1_vec);
    /*
        Destination element 0 gets source element 1 → imm8[1:0] = 01
                Destination element 1 gets source element 2 → imm8[3:2] = 10
                Destination element 2 gets source element 3 → imm8[5:4] = 11
                Destination element 3 gets source element 0 → imm8[7:6] = 00
    r shift 10010011
    l shift 01100100
        */
    data = _mm512_shuffle_epi32(data, 0b10010011);
    // PRINT_M512(accs);
  }
  // accs = _mm512_bslli_epi128(accs, 7);
  return accs;
}

__m256i round_all16x2(__m256i accs, __m256i data,
                             const __m256i prime1_vec) {
  for (int i = 0; i < 4; i++) {
    accs = _mm256_add_epi64(accs, _mm256_mullo_epi64(data, prime1_vec));
    accs = _mm256_rol_epi64(accs, 17);
    accs = _mm256_mullo_epi64(accs, prime1_vec);
    /*
        Destination element 0 gets source element 1 → imm8[1:0] = 01
                Destination element 1 gets source element 2 → imm8[3:2] = 10
                Destination element 2 gets source element 3 → imm8[5:4] = 11
                Destination element 3 gets source element 0 → imm8[7:6] = 00
    r shift 10010011
    l shift 01100100
        */
    data = _mm256_shuffle_epi32(data, 0b10010011);
    // PRINT_M512(accs);
  }
  // accs = _mm512_bslli_epi128(accs, 7);
  return accs;
}

void xxhash16x4(const uint8_t *buf, const uint32_t seed, uint8_t *out) {
  // pr_info("is aligned %d\n", ((unsigned long)buf % 64) == 0);
  // kernel_fpu_begin();
  __m512i input = _mm512_loadu_si512((__m512i *)buf);
  // PRINT_M512(input);
  uint32_t acc1 = seed + PRIME32_1 + PRIME32_2;
  uint32_t acc2 = seed + PRIME32_2;
  uint32_t acc3 = seed;
  uint32_t acc4 = seed - PRIME32_1;
  // // // init prime vect

  // // // I'm assuming fixed 16 bytes
  __m512i prime1_vec = _mm512_set1_epi32(PRIME32_1);

  __m512i accs =
      _mm512_set_epi32(acc4, acc3, acc2, acc1, acc4, acc3, acc2, acc1, acc4,
                       acc3, acc2, acc1, acc4, acc3, acc2, acc1);

  __m512i res = round_all16x4(accs, input, prime1_vec);
  // PRINT_M512(res);

  _mm512_storeu_si512((__m512i *)out, res);
  // PRINT OUT
  // kernel_fpu_end();
  return;
}

inline void xxhash16x2(const uint8_t *buf, const uint32_t seed, uint8_t *out) {
  // kernel_fpu_begin();

  __m256i input = _mm256_loadu_si256((__m256i *)buf);

  uint32_t acc1 = seed + PRIME32_1 + PRIME32_2;
  uint32_t acc2 = seed + PRIME32_2;
  uint32_t acc3 = seed;
  uint32_t acc4 = seed - PRIME32_1;
  // // // init prime vect

  // // // I'm assuming fixed 16 bytes
  __m256i prime1_vec = _mm256_set1_epi32(PRIME32_1);

  __m256i accs =
      _mm256_set_epi32(acc4, acc3, acc2, acc1, acc4, acc3, acc2, acc1);

  __m256i res = round_all16x2(accs, input, prime1_vec);

  _mm256_storeu_si256((__m256i *)out, res);
  // kernel_fpu_end();
  return;
}

// __bpf_kfunc void xxhash(uint8_t *buf, uint32_t seed, uint8_t *out, __u64 b_len) {
//   if (b_len == 1 || b_len > 4) {
//     out = NULL; //error
//     return;
//   } 
  
//   if (b_len == 2) {
//     kernel_fpu_begin();
//     xxhash16x2(buf, seed, out);
//     kernel_fpu_end();
//   } else if (b_len > 2) {
//     kernel_fpu_begin();
//     xxhash16x4(buf, seed, out);
//     kernel_fpu_end();
//   }
// }
