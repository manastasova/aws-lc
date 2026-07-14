// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#ifndef OPENSSL_HEADER_CRYPTO_CURVE448_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_CURVE448_INTERNAL_H

#include <openssl/base.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif


void ED448_keypair_from_seed(uint8_t out_public_key[57],
    uint8_t out_private_key[57],
    const uint8_t seed[57]);

int ED448_sign(uint8_t out_sig[114],
    const uint8_t *message, size_t message_len,
    const uint8_t private_key[57],
    const uint8_t public_key[57]);

int ED448_verify(const uint8_t *message, size_t message_len,
    const uint8_t signature[114],
    const uint8_t public_key[57]);

#if defined(__cplusplus)
}
#endif

#endif  // OPENSSL_HEADER_CRYPTO_CURVE448_INTERNAL_H
