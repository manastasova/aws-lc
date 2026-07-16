// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
//
// Portions Copyright 2017-2024 The OpenSSL Project Authors. All Rights Reserved.
// Portions Copyright 2015-2016 Cryptography Research, Inc.
// Originally written by Mike Hamburg.

#include <string.h>

#include <openssl/mem.h>
#include <openssl/evp.h>

#include "word448.h"
#include "field448.h"
#include "point_448.h"
#include "internal.h"
#include "../fipsmodule/sha/internal.h"

#define COFACTOR 4
#define C448_EDDSA_ENCODE_RATIO 4

static const uint8_t DOM4_PREFIX[] = {
    'S', 'i', 'g', 'E', 'd', '4', '4', '8', 0x00, 0x00
};
#define DOM4_PREFIX_LEN 10

static int hash_init_with_dom(EVP_MD_CTX *hashctx) {
    if (!EVP_DigestInit_ex(hashctx, EVP_shake256(), NULL) ||
        !EVP_DigestUpdate(hashctx, DOM4_PREFIX, DOM4_PREFIX_LEN))
        return 0;
    return 1;
}

static int oneshot_hash(uint8_t *out, size_t outlen,
    const uint8_t *in, size_t inlen) {
    return SHAKE256(in, inlen, out, outlen) != NULL;
}

static void clamp(uint8_t secret_scalar_ser[EDDSA_448_PRIVATE_BYTES]) {
    secret_scalar_ser[0] &= -COFACTOR;
    secret_scalar_ser[EDDSA_448_PRIVATE_BYTES - 1] = 0;
    secret_scalar_ser[EDDSA_448_PRIVATE_BYTES - 2] |= 0x80;
}

int ED448_keypair_from_seed(uint8_t out_public_key[57],
    uint8_t out_private_key[57],
    const uint8_t seed[57]) {
    uint8_t secret_scalar_ser[EDDSA_448_PRIVATE_BYTES];
    curve448_scalar_t secret_scalar;
    unsigned int c;
    curve448_point_t p;

    memcpy(out_private_key, seed, EDDSA_448_PRIVATE_BYTES);

    if (!oneshot_hash(secret_scalar_ser, sizeof(secret_scalar_ser),
            seed, EDDSA_448_PRIVATE_BYTES)) {
        OPENSSL_cleanse(secret_scalar_ser, sizeof(secret_scalar_ser));
        return 0;
    }

    clamp(secret_scalar_ser);

    curve448_scalar_decode_long(secret_scalar, secret_scalar_ser,
        sizeof(secret_scalar_ser));

    for (c = 1; c < C448_EDDSA_ENCODE_RATIO; c <<= 1)
        curve448_scalar_halve(secret_scalar, secret_scalar);

    curve448_precomputed_scalarmul(p, curve448_precomputed_base, secret_scalar);

    curve448_point_mul_by_ratio_and_encode_like_eddsa(out_public_key, p);

    curve448_scalar_destroy(secret_scalar);
    curve448_point_destroy(p);
    OPENSSL_cleanse(secret_scalar_ser, sizeof(secret_scalar_ser));
    CONSTTIME_DECLASSIFY(out_public_key, EDDSA_448_PUBLIC_BYTES);
    return 1;
}

int ED448_sign(uint8_t out_sig[114],
    const uint8_t *message, size_t message_len,
    const uint8_t private_key[57],
    const uint8_t public_key[57]) {
    curve448_scalar_t secret_scalar;
    EVP_MD_CTX hashctx;
    int ret = 0;
    curve448_scalar_t nonce_scalar;
    uint8_t nonce_point[EDDSA_448_PUBLIC_BYTES] = {0};
    unsigned int c;
    curve448_scalar_t challenge_scalar;

    EVP_MD_CTX_init(&hashctx);

    {
        uint8_t expanded[EDDSA_448_PRIVATE_BYTES * 2];

        if (!oneshot_hash(expanded, sizeof(expanded), private_key,
                EDDSA_448_PRIVATE_BYTES)) {
            OPENSSL_cleanse(expanded, sizeof(expanded));
            goto err;
        }
        clamp(expanded);
        curve448_scalar_decode_long(secret_scalar, expanded,
            EDDSA_448_PRIVATE_BYTES);

        if (!hash_init_with_dom(&hashctx) ||
            !EVP_DigestUpdate(&hashctx,
                expanded + EDDSA_448_PRIVATE_BYTES,
                EDDSA_448_PRIVATE_BYTES) ||
            !EVP_DigestUpdate(&hashctx, message, message_len)) {
            OPENSSL_cleanse(expanded, sizeof(expanded));
            goto err;
        }
        OPENSSL_cleanse(expanded, sizeof(expanded));
    }

    {
        uint8_t nonce[2 * EDDSA_448_PRIVATE_BYTES];

        if (!EVP_DigestFinalXOF(&hashctx, nonce, sizeof(nonce)))
            goto err;
        curve448_scalar_decode_long(nonce_scalar, nonce, sizeof(nonce));
        OPENSSL_cleanse(nonce, sizeof(nonce));
    }

    {
        curve448_scalar_t nonce_scalar_2;
        curve448_point_t p;

        curve448_scalar_halve(nonce_scalar_2, nonce_scalar);
        for (c = 2; c < C448_EDDSA_ENCODE_RATIO; c <<= 1)
            curve448_scalar_halve(nonce_scalar_2, nonce_scalar_2);

        curve448_precomputed_scalarmul(p, curve448_precomputed_base,
            nonce_scalar_2);
        curve448_point_mul_by_ratio_and_encode_like_eddsa(nonce_point, p);
        curve448_point_destroy(p);
        curve448_scalar_destroy(nonce_scalar_2);
    }

    {
        uint8_t challenge[2 * EDDSA_448_PRIVATE_BYTES];

        if (!hash_init_with_dom(&hashctx) ||
            !EVP_DigestUpdate(&hashctx, nonce_point, sizeof(nonce_point)) ||
            !EVP_DigestUpdate(&hashctx, public_key, EDDSA_448_PUBLIC_BYTES) ||
            !EVP_DigestUpdate(&hashctx, message, message_len) ||
            !EVP_DigestFinalXOF(&hashctx, challenge, sizeof(challenge)))
            goto err;

        curve448_scalar_decode_long(challenge_scalar, challenge,
            sizeof(challenge));
        OPENSSL_cleanse(challenge, sizeof(challenge));
    }

    curve448_scalar_mul(challenge_scalar, challenge_scalar, secret_scalar);
    curve448_scalar_add(challenge_scalar, challenge_scalar, nonce_scalar);

    OPENSSL_cleanse(out_sig, EDDSA_448_SIGNATURE_BYTES);
    memcpy(out_sig, nonce_point, sizeof(nonce_point));
    curve448_scalar_encode(&out_sig[EDDSA_448_PUBLIC_BYTES], challenge_scalar);

    CONSTTIME_DECLASSIFY(out_sig, EDDSA_448_SIGNATURE_BYTES);
    ret = 1;
err:
    curve448_scalar_destroy(secret_scalar);
    curve448_scalar_destroy(nonce_scalar);
    curve448_scalar_destroy(challenge_scalar);
    EVP_MD_CTX_cleanup(&hashctx);
    return ret;
}

int ED448_verify(const uint8_t *message, size_t message_len,
    const uint8_t signature[114],
    const uint8_t public_key[57]) {
    curve448_point_t pk_point, r_point;
    c448_error_t error;
    curve448_scalar_t challenge_scalar;
    curve448_scalar_t response_scalar;
    static const uint8_t order[] = {
        0xF3, 0x44, 0x58, 0xAB, 0x92, 0xC2, 0x78, 0x23, 0x55, 0x8F, 0xC5, 0x8D,
        0x72, 0xC2, 0x6C, 0x21, 0x90, 0x36, 0xD6, 0xAE, 0x49, 0xDB, 0x4E, 0xC4,
        0xE9, 0x23, 0xCA, 0x7C, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F, 0x00
    };
    int i;

    for (i = EDDSA_448_PUBLIC_BYTES - 1; i >= 0; i--) {
        if (signature[i + EDDSA_448_PUBLIC_BYTES] > order[i])
            return 0;
        if (signature[i + EDDSA_448_PUBLIC_BYTES] < order[i])
            break;
    }
    if (i < 0)
        return 0;

    error = curve448_point_decode_like_eddsa_and_mul_by_ratio(pk_point,
        public_key);
    if (C448_SUCCESS != error)
        return 0;

    error = curve448_point_decode_like_eddsa_and_mul_by_ratio(r_point,
        signature);
    if (C448_SUCCESS != error)
        return 0;

    {
        EVP_MD_CTX hashctx;
        uint8_t challenge[2 * EDDSA_448_PRIVATE_BYTES];

        EVP_MD_CTX_init(&hashctx);
        if (!hash_init_with_dom(&hashctx) ||
            !EVP_DigestUpdate(&hashctx, signature, EDDSA_448_PUBLIC_BYTES) ||
            !EVP_DigestUpdate(&hashctx, public_key, EDDSA_448_PUBLIC_BYTES) ||
            !EVP_DigestUpdate(&hashctx, message, message_len) ||
            !EVP_DigestFinalXOF(&hashctx, challenge, sizeof(challenge))) {
            EVP_MD_CTX_cleanup(&hashctx);
            return 0;
        }

        EVP_MD_CTX_cleanup(&hashctx);
        curve448_scalar_decode_long(challenge_scalar, challenge,
            sizeof(challenge));
        OPENSSL_cleanse(challenge, sizeof(challenge));
    }

    curve448_scalar_sub(challenge_scalar, curve448_scalar_zero,
        challenge_scalar);

    curve448_scalar_decode_long(response_scalar,
        &signature[EDDSA_448_PUBLIC_BYTES],
        EDDSA_448_PRIVATE_BYTES);

    curve448_base_double_scalarmul_non_secret(pk_point,
        response_scalar, pk_point, challenge_scalar);

    return curve448_point_eq(pk_point, r_point) == C448_TRUE;
}
