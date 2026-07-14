// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
//
// Portions Copyright 2017-2023 The OpenSSL Project Authors. All Rights Reserved.
// Portions Copyright 2015-2016 Cryptography Research, Inc.
// Originally written by Mike Hamburg.

#ifndef OPENSSL_HEADER_CRYPTO_CURVE448_POINT448_H
#define OPENSSL_HEADER_CRYPTO_CURVE448_POINT448_H

#include "curve448utils.h"
#include "field448.h"

// Comb config: number of combs, n, t, s.
#define COMBS_N 5
#define COMBS_T 5
#define COMBS_S 18

// Projective Niels coordinates.
typedef struct {
    gf a, b, c;
} niels_s, niels_t[1];
typedef struct {
    niels_t n;
    gf z;
} pniels_t[1];

// Precomputed base.
struct curve448_precomputed_s {
    niels_t table[COMBS_N << (COMBS_T - 1)];
};

#define C448_SCALAR_LIMBS ((446 - 1) / C448_WORD_BITS + 1)
#define C448_SCALAR_BITS 446
#define C448_SCALAR_BYTES 56

#define X448_ENCODE_RATIO 2
#define X448_PUBLIC_BYTES 56
#define X448_PRIVATE_BYTES 56

// Twisted Edwards extended homogeneous coordinates.
typedef struct curve448_point_s {
    gf x, y, z, t;
} curve448_point_t[1];

typedef struct curve448_precomputed_s curve448_precomputed_s;

// Scalar is stored packed.
typedef struct curve448_scalar_s {
    c448_word_t limb[C448_SCALAR_LIMBS];
} curve448_scalar_t[1];

extern const curve448_scalar_t curve448_scalar_one;
extern const curve448_scalar_t curve448_scalar_zero;
extern const curve448_point_t curve448_point_identity;
extern const struct curve448_precomputed_s *curve448_precomputed_base;
extern const niels_t *curve448_wnaf_base;

c448_error_t curve448_scalar_decode(curve448_scalar_t out,
    const unsigned char ser[C448_SCALAR_BYTES]);

void curve448_scalar_decode_long(curve448_scalar_t out,
    const unsigned char *ser, size_t ser_len);

void curve448_scalar_encode(unsigned char ser[C448_SCALAR_BYTES],
    const curve448_scalar_t s);

void curve448_scalar_add(curve448_scalar_t out,
    const curve448_scalar_t a, const curve448_scalar_t b);

void curve448_scalar_sub(curve448_scalar_t out,
    const curve448_scalar_t a, const curve448_scalar_t b);

void curve448_scalar_mul(curve448_scalar_t out,
    const curve448_scalar_t a, const curve448_scalar_t b);

void curve448_scalar_halve(curve448_scalar_t out,
    const curve448_scalar_t a);

static inline void curve448_scalar_copy(curve448_scalar_t out,
    const curve448_scalar_t a) {
    *out = *a;
}

static inline void curve448_point_copy(curve448_point_t a,
    const curve448_point_t b) {
    *a = *b;
}

c448_bool_t curve448_point_eq(const curve448_point_t a,
    const curve448_point_t b);

void curve448_point_double(curve448_point_t two_a,
    const curve448_point_t a);

c448_error_t c448_x448_int(uint8_t out[X448_PUBLIC_BYTES],
    const uint8_t base[X448_PUBLIC_BYTES],
    const uint8_t scalar[X448_PRIVATE_BYTES]);

void curve448_point_mul_by_ratio_and_encode_like_x448(
    uint8_t out[X448_PUBLIC_BYTES],
    const curve448_point_t p);

void c448_x448_derive_public_key(uint8_t out[X448_PUBLIC_BYTES],
    const uint8_t scalar[X448_PRIVATE_BYTES]);

void curve448_precomputed_scalarmul(curve448_point_t scaled,
    const curve448_precomputed_s *base,
    const curve448_scalar_t scalar);

void curve448_base_double_scalarmul_non_secret(curve448_point_t combo,
    const curve448_scalar_t scalar1,
    const curve448_point_t base2,
    const curve448_scalar_t scalar2);

c448_bool_t curve448_point_valid(const curve448_point_t to_test);

void curve448_scalar_destroy(curve448_scalar_t scalar);
void curve448_point_destroy(curve448_point_t point);

#endif  // OPENSSL_HEADER_CRYPTO_CURVE448_POINT448_H
