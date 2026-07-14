// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/mem.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  // Fuzz the Ed448 signature verification surface with attacker-controlled
  // public key, message, and signature bytes.
  // Layout: [pubkey (57)] [signature (114)] [message (remainder)]
  if (len < 57 + 114) {
    return 0;
  }

  const uint8_t *pubkey = buf;
  const uint8_t *sig = buf + 57;
  const uint8_t *msg = buf + 57 + 114;
  size_t msg_len = len - 57 - 114;

  EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, nullptr,
                                                pubkey, 57);
  if (pkey == nullptr) {
    ERR_clear_error();
    return 0;
  }

  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  if (md_ctx != nullptr) {
    if (EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey)) {
      EVP_DigestVerify(md_ctx, sig, 114, msg, msg_len);
    }
    EVP_MD_CTX_free(md_ctx);
  }

  EVP_PKEY_free(pkey);
  ERR_clear_error();
  return 0;
}
