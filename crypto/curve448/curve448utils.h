// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
//
// Portions Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
// Portions Copyright 2015 Cryptography Research, Inc.
// Originally written by Mike Hamburg.

#ifndef OPENSSL_HEADER_CRYPTO_CURVE448_CURVE448UTILS_H
#define OPENSSL_HEADER_CRYPTO_CURVE448_CURVE448UTILS_H

#include <openssl/base.h>

#include "../internal.h"

#ifndef C448_WORD_BITS
#if defined(BORINGSSL_HAS_UINT128)
#define C448_WORD_BITS 64
#else
#define C448_WORD_BITS 32
#endif
#endif

#if C448_WORD_BITS == 64
typedef uint64_t c448_word_t;
typedef int64_t c448_sword_t;
typedef uint64_t c448_bool_t;
typedef uint128_t c448_dword_t;
typedef int128_t c448_dsword_t;
#elif C448_WORD_BITS == 32
typedef uint32_t c448_word_t;
typedef int32_t c448_sword_t;
typedef uint32_t c448_bool_t;
typedef uint64_t c448_dword_t;
typedef int64_t c448_dsword_t;
#else
#error "Only supporting C448_WORD_BITS = 32 or 64"
#endif

#define C448_TRUE (0 - (c448_bool_t)1)
#define C448_FALSE 0

typedef enum {
    C448_SUCCESS = -1,
    C448_FAILURE = 0
} c448_error_t;

static inline c448_error_t c448_succeed_if(c448_bool_t x) {
    return (c448_error_t)x;
}

#endif  // OPENSSL_HEADER_CRYPTO_CURVE448_CURVE448UTILS_H
