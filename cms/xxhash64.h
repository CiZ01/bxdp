/*
 * Copyright (c) 2015 Daniel Kirchner
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#pragma once


#define PRIME1 11400714785074694791ULL
#define PRIME2 14029467366897019727ULL
#define PRIME3 1609587929392839161ULL
#define PRIME4 9650029242287828579ULL
#define PRIME5 2870177450012600261ULL

static __always_inline __u64 rotl (__u64 x, int r) {
    return ((x << r) | (x >> (64 - r)));
}

static __always_inline __u64 mix1 (const __u64 h, const __u64 prime, int rshift) {
    return (h ^ (h >> rshift)) * prime;
}

static __always_inline __u64 mix2 (const __u64 p, const __u64 v) {
    return rotl (v + p * PRIME2, 31) * PRIME1;
}

static __always_inline __u64 mix3 (const __u64 h, const __u64 v) {
    return (h ^ mix2 (v, 0)) * PRIME1 + PRIME4;
}

static __always_inline __u32 endian32 (const char *v) {
        return (__u32)((__u8)(v[0]))|((__u32)((__u8)(v[1]))<<8)
               |((__u32)((__u8)(v[2]))<<16)|((__u32)((__u8)(v[3]))<<24);
    }

static __always_inline __u64 endian64 (const char *v) {
    return (__u64)((__u8)(v[0]))|((__u64)((__u8)(v[1]))<<8)
            |((__u64)((__u8)(v[2]))<<16)|((__u64)((__u8)(v[3]))<<24)
            |((__u64)((__u8)(v[4]))<<32)|((__u64)((__u8)(v[5]))<<40)
            |((__u64)((__u8)(v[6]))<<48)|((__u64)((__u8)(v[7]))<<56);
}

static __always_inline __u64 fetch64 (const char *p, const __u64 v) {
    return mix2 (endian64 (p), v);
}

static __always_inline __u64 fetch32 (const char *p) {
    return (__u64)(endian32 (p)) * PRIME1;
}

static __always_inline __u64 fetch8 (const char *p) {
    return (__u8)(*p) * PRIME5;
}

static __u64 finalize (const __u64 h, const char *p, __u64 len) {
    return (len >= 8) ? (finalize (rotl (h ^ fetch64 (p, 0), 27) * PRIME1 + PRIME4, p + 8, len - 8)) :
            ((len >= 4) ? (finalize (rotl (h ^ fetch32 (p), 23) * PRIME2 + PRIME3, p + 4, len - 4)) :
            ((len > 0) ? (finalize (rotl (h ^ fetch8 (p), 11) * PRIME1, p + 1, len - 1)) :
                (mix1 (mix1 (mix1 (h, PRIME2, 33), PRIME3, 29), 1, 32))));
}

static __u64 h32bytes_4 (const char *p, __u64 len, const __u64 v1,const __u64 v2, const __u64 v3, const __u64 v4) {
    return (len >= 32) ? h32bytes_4 (p + 32, len - 32, fetch64 (p, v1), fetch64 (p + 8, v2), fetch64 (p + 16, v3), fetch64 (p + 24, v4)) :
            mix3 (mix3 (mix3 (mix3 (rotl (v1, 1) + rotl (v2, 7) + rotl (v3, 12) + rotl (v4, 18), v1), v2), v3), v4);
}

static __u64 h32bytes_3 (const char *p, __u64 len, const __u64 seed) {
    return h32bytes_4 (p, len, seed + PRIME1 + PRIME2, seed + PRIME2, seed, seed - PRIME1);
}

static __u64 xxhash64 (const char *p, __u64 len, __u64 seed) {
    return finalize((len >= 32 ? h32bytes_3(p, len, seed) : seed + PRIME5) + len, p + (len & ~0x1F), len & 0x1F);
}