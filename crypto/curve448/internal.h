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

// Canonical Ed448 byte lengths. These are the single source of truth for the
// key/seed/signature sizes and are reused by the EVP layer (see
// crypto/evp_extra/internal.h, which includes this header).
#define ED448_SEED_LEN 57
#define ED448_PUBLIC_KEY_LEN 57
#define ED448_SIGNATURE_LEN 114

// ED448_keypair_from_seed derives the public key and stores the seed as the
// private key. It returns one on success and zero on failure (e.g. the
// internal hash operation failed).
int ED448_keypair_from_seed(uint8_t out_public_key[ED448_PUBLIC_KEY_LEN],
    uint8_t out_private_key[ED448_SEED_LEN],
    const uint8_t seed[ED448_SEED_LEN]);

int ED448_sign(uint8_t out_sig[ED448_SIGNATURE_LEN],
    const uint8_t *message, size_t message_len,
    const uint8_t private_key[ED448_SEED_LEN],
    const uint8_t public_key[ED448_PUBLIC_KEY_LEN]);

int ED448_verify(const uint8_t *message, size_t message_len,
    const uint8_t signature[ED448_SIGNATURE_LEN],
    const uint8_t public_key[ED448_PUBLIC_KEY_LEN]);

#if defined(__cplusplus)
}
#endif

#endif  // OPENSSL_HEADER_CRYPTO_CURVE448_INTERNAL_H
