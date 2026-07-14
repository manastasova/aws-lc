// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
//
// Portions Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
// Portions Copyright 2016 Cryptography Research, Inc.
// Originally written by Mike Hamburg.

#ifndef OPENSSL_HEADER_CRYPTO_CURVE448_ARCH32_INTRINSICS_H
#define OPENSSL_HEADER_CRYPTO_CURVE448_ARCH32_INTRINSICS_H

#include <stdint.h>

#include "../../internal.h"

#define ARCH_WORD_BITS 32

static inline uint32_t word_is_zero(uint32_t a) {
    return (uint32_t)constant_time_is_zero_w((crypto_word_t)a);
}

static inline uint64_t widemul(uint32_t a, uint32_t b) {
    return ((uint64_t)a) * b;
}

#endif  // OPENSSL_HEADER_CRYPTO_CURVE448_ARCH32_INTRINSICS_H
