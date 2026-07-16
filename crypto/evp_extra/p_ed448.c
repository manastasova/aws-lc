// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <openssl/evp.h>

#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/rand.h>

#include "../fipsmodule/evp/internal.h"
#include "../internal.h"
#include "internal.h"
#include "../curve448/internal.h"

// Ed448 has no parameters to copy.
static int pkey_ed448_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src) { return 1; }

static int pkey_ed448_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
  ED448_KEY *key = OPENSSL_malloc(sizeof(ED448_KEY));
  if (key == NULL) {
    return 0;
  }

  // Ed448 keys are derived from a random 57-byte seed. Generate the seed and
  // expand it into the public key and stored seed.
  uint8_t seed[ED448_SEED_LEN];
  if (!RAND_bytes(seed, sizeof(seed)) ||
      !ED448_keypair_from_seed(key->pub, key->seed, seed)) {
    OPENSSL_cleanse(seed, sizeof(seed));
    OPENSSL_cleanse(key, sizeof(ED448_KEY));
    OPENSSL_free(key);
    return 0;
  }
  OPENSSL_cleanse(seed, sizeof(seed));
  key->has_private = 1;

  evp_pkey_set0(pkey, &ed448_asn1_meth, key);
  return 1;
}

static int pkey_ed448_sign_message(EVP_PKEY_CTX *ctx, uint8_t *sig,
                                   size_t *siglen, const uint8_t *tbs,
                                   size_t tbslen) {
  ED448_KEY *key = ctx->pkey->pkey.ptr;
  if (!key->has_private) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NOT_A_PRIVATE_KEY);
    return 0;
  }

  if (sig == NULL) {
    *siglen = ED448_SIGNATURE_LEN;
    return 1;
  }

  if (*siglen < ED448_SIGNATURE_LEN) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (!ED448_sign(sig, tbs, tbslen, key->seed, key->pub)) {
    return 0;
  }

  *siglen = ED448_SIGNATURE_LEN;
  return 1;
}

static int pkey_ed448_verify_message(EVP_PKEY_CTX *ctx, const uint8_t *sig,
                                     size_t siglen, const uint8_t *tbs,
                                     size_t tbslen) {
  ED448_KEY *key = ctx->pkey->pkey.ptr;
  if (siglen != ED448_SIGNATURE_LEN ||
      !ED448_verify(tbs, tbslen, sig, key->pub)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_SIGNATURE);
    return 0;
  }

  return 1;
}

const EVP_PKEY_METHOD ed448_pkey_meth = {
    EVP_PKEY_ED448,
    NULL /* init */,
    pkey_ed448_copy,
    NULL /* cleanup */,
    pkey_ed448_keygen,
    NULL /* sign_init */,
    NULL /* sign */,
    pkey_ed448_sign_message,
    NULL /* verify_init */,
    NULL /* verify */,
    pkey_ed448_verify_message,
    NULL /* verify_recover */,
    NULL /* encrypt */,
    NULL /* decrypt */,
    NULL /* derive */,
    NULL /* paramgen */,
    NULL /* ctrl */,
    NULL /* ctrl_str */,
    NULL /* keygen_deterministic */,
    NULL /* encapsulate_deterministic */,
    NULL /* encapsulate */,
    NULL /* decapsulate */,
};
