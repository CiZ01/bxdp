#pragma once


#include <rte_common.h>
#include <immintrin.h>


#define GET_FIST_32BIT(x) ((x) & 0xFFFFFFFF)

#define PRIME32_1 0x9E3779B1
#define PRIME32_2 0x85EBCA77
#define PRIME32_3 0xC2B2AE3D
#define PRIME32_4 0x27D4EB2F
#define PRIME32_5 0x165667B1

void xxhash16x4(const uint8_t *buf, const uint32_t seed, uint8_t *out);
