// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
//
// Portions Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
// Portions Copyright 2014 Cryptography Research, Inc.
// Originally written by Mike Hamburg.

#ifndef OPENSSL_HEADER_CRYPTO_CURVE448_WORD448_H
#define OPENSSL_HEADER_CRYPTO_CURVE448_WORD448_H

#include <string.h>
#include <assert.h>

#include "../internal.h"
#include "curve448utils.h"

#if defined(BORINGSSL_HAS_UINT128)
#include "arch_64/arch_intrinsics.h"
#else
#include "arch_32/arch_intrinsics.h"
#endif

#if (ARCH_WORD_BITS == 64)
typedef uint64_t word_t, mask_t;
typedef uint128_t dword_t;
typedef int32_t hsword_t;
typedef int64_t sword_t;
typedef int128_t dsword_t;
#elif (ARCH_WORD_BITS == 32)
typedef uint32_t word_t, mask_t;
typedef uint64_t dword_t;
typedef int16_t hsword_t;
typedef int32_t sword_t;
typedef int64_t dsword_t;
#else
#error "Only 32- and 64-bit architectures are supported."
#endif

#if C448_WORD_BITS == 64
#define SC_LIMB(x) (x)
#elif C448_WORD_BITS == 32
#define SC_LIMB(x) ((uint32_t)(x)), ((x) >> 32)
#else
#error "Only 32- and 64-bit architectures are supported."
#endif

#if C448_WORD_BITS == 64
#define value_barrier_c448(x) value_barrier_u64(x)
#elif C448_WORD_BITS == 32
#define value_barrier_c448(x) value_barrier_u32(x)
#endif

static inline c448_bool_t mask_to_bool(mask_t m) {
    return (c448_sword_t)(sword_t)m;
}

static inline mask_t bool_to_mask(c448_bool_t m) {
    mask_t ret = 0;
    unsigned int i;
    unsigned int limit = sizeof(c448_bool_t) / sizeof(mask_t);

    if (limit < 1)
        limit = 1;
    for (i = 0; i < limit; i++)
        ret |= ~word_is_zero(m >> (i * 8 * sizeof(word_t)));

    return ret;
}

#endif  // OPENSSL_HEADER_CRYPTO_CURVE448_WORD448_H
