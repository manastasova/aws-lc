// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// aws-lc target implementation wrapper for the Ed448 differential harness.
// This file is compiled against aws-lc's OWN headers only.

#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdint.h>

// Sign using aws-lc's Ed448 implementation.
// Returns 1 on success, 0 on failure (including "not yet implemented").
int awslc_ed448_sign(uint8_t *sig_out, size_t *sig_len_out,
                     const uint8_t *privkey_seed, size_t seed_len,
                     const uint8_t *msg, size_t msg_len) {
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED448, NULL,
                                                 privkey_seed, seed_len);
  if (!pkey) {
    ERR_clear_error();
    return 0;
  }

  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    EVP_PKEY_free(pkey);
    return 0;
  }

  int ret = 0;
  if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) != 1) {
    goto done;
  }

  *sig_len_out = 114;
  if (EVP_DigestSign(md_ctx, sig_out, sig_len_out, msg, msg_len) != 1) {
    goto done;
  }
  ret = 1;

done:
  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pkey);
  if (!ret) {
    ERR_clear_error();
  }
  return ret;
}

// Verify using aws-lc's Ed448 implementation.
int awslc_ed448_verify(const uint8_t *pubkey, size_t pubkey_len,
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t *sig, size_t sig_len) {
  EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, NULL,
                                                pubkey, pubkey_len);
  if (!pkey) {
    ERR_clear_error();
    return 0;
  }

  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    EVP_PKEY_free(pkey);
    return 0;
  }

  int ret = 0;
  if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) != 1) {
    goto done;
  }

  ret = (EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len) == 1) ? 1 : 0;

done:
  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pkey);
  ERR_clear_error();
  return ret;
}

// Derive public key from seed using aws-lc.
int awslc_ed448_pubkey_from_seed(uint8_t *pubkey_out, size_t *pubkey_len_out,
                                 const uint8_t *seed, size_t seed_len) {
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED448, NULL,
                                                 seed, seed_len);
  if (!pkey) {
    ERR_clear_error();
    return 0;
  }

  *pubkey_len_out = 57;
  int ret = EVP_PKEY_get_raw_public_key(pkey, pubkey_out, pubkey_len_out);
  EVP_PKEY_free(pkey);
  if (!ret) {
    ERR_clear_error();
  }
  return ret;
}
