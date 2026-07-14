// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
//
// Portions Copyright 2017-2022 The OpenSSL Project Authors. All Rights Reserved.
// Portions Copyright 2016 Cryptography Research, Inc.
// Originally written by Mike Hamburg.

#ifndef OPENSSL_HEADER_CRYPTO_CURVE448_ARCH64_INTRINSICS_H
#define OPENSSL_HEADER_CRYPTO_CURVE448_ARCH64_INTRINSICS_H

#include <stdint.h>

#include "../../internal.h"

#define ARCH_WORD_BITS 64

static inline uint64_t word_is_zero(uint64_t a) {
    return constant_time_is_zero_w(a);
}

static inline uint128_t widemul(uint64_t a, uint64_t b) {
    return ((uint128_t)a) * b;
}

#endif  // OPENSSL_HEADER_CRYPTO_CURVE448_ARCH64_INTRINSICS_H
