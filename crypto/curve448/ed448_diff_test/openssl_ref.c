// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// OpenSSL reference implementation wrapper for the Ed448 differential harness.
// Uses dlopen to load OpenSSL's libcrypto.so at runtime, avoiding symbol
// collisions with aws-lc (which is statically linked).

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// Function pointer types matching OpenSSL's API
typedef void* (*pEVP_PKEY_new_raw_private_key_fn)(int type, void *engine,
                                                   const unsigned char *key,
                                                   size_t keylen);
typedef void* (*pEVP_PKEY_new_raw_public_key_fn)(int type, void *engine,
                                                  const unsigned char *key,
                                                  size_t keylen);
typedef void* (*pEVP_MD_CTX_new_fn)(void);
typedef void  (*pEVP_MD_CTX_free_fn)(void *ctx);
typedef void  (*pEVP_PKEY_free_fn)(void *pkey);
typedef int   (*pEVP_DigestSignInit_fn)(void *ctx, void **pctx, void *type,
                                         void *e, void *pkey);
typedef int   (*pEVP_DigestSign_fn)(void *ctx, unsigned char *sigret,
                                     size_t *siglen, const unsigned char *tbs,
                                     size_t tbslen);
typedef int   (*pEVP_DigestVerifyInit_fn)(void *ctx, void **pctx, void *type,
                                           void *e, void *pkey);
typedef int   (*pEVP_DigestVerify_fn)(void *ctx, const unsigned char *sigret,
                                       size_t siglen, const unsigned char *tbs,
                                       size_t tbslen);
typedef int   (*pEVP_PKEY_get_raw_public_key_fn)(void *pkey,
                                                  unsigned char *pub,
                                                  size_t *len);
typedef void  (*pERR_clear_error_fn)(void);

static void *ossl_handle = NULL;
static pEVP_PKEY_new_raw_private_key_fn ossl_new_raw_priv = NULL;
static pEVP_PKEY_new_raw_public_key_fn  ossl_new_raw_pub = NULL;
static pEVP_MD_CTX_new_fn              ossl_md_ctx_new = NULL;
static pEVP_MD_CTX_free_fn             ossl_md_ctx_free = NULL;
static pEVP_PKEY_free_fn               ossl_pkey_free = NULL;
static pEVP_DigestSignInit_fn          ossl_digest_sign_init = NULL;
static pEVP_DigestSign_fn              ossl_digest_sign = NULL;
static pEVP_DigestVerifyInit_fn        ossl_digest_verify_init = NULL;
static pEVP_DigestVerify_fn            ossl_digest_verify = NULL;
static pEVP_PKEY_get_raw_public_key_fn ossl_get_raw_pub = NULL;
static pERR_clear_error_fn             ossl_err_clear = NULL;

// NID_ED448 in OpenSSL 3.x (from openssl/include/openssl/obj_mac.h)
#define OSSL_EVP_PKEY_ED448 1088

int openssl_ed448_init(const char *libcrypto_path) {
  ossl_handle = dlopen(libcrypto_path, RTLD_NOW | RTLD_LOCAL);
  if (!ossl_handle) {
    fprintf(stderr, "dlopen(%s) failed: %s\n", libcrypto_path, dlerror());
    return 0;
  }

  // Resolve EVP_PKEY_ED448 NID by checking what OpenSSL uses
  // OpenSSL 3.x uses NID_ED448=1087
  ossl_new_raw_priv = (pEVP_PKEY_new_raw_private_key_fn)
      dlsym(ossl_handle, "EVP_PKEY_new_raw_private_key");
  ossl_new_raw_pub = (pEVP_PKEY_new_raw_public_key_fn)
      dlsym(ossl_handle, "EVP_PKEY_new_raw_public_key");
  ossl_md_ctx_new = (pEVP_MD_CTX_new_fn)dlsym(ossl_handle, "EVP_MD_CTX_new");
  ossl_md_ctx_free = (pEVP_MD_CTX_free_fn)dlsym(ossl_handle, "EVP_MD_CTX_free");
  ossl_pkey_free = (pEVP_PKEY_free_fn)dlsym(ossl_handle, "EVP_PKEY_free");
  ossl_digest_sign_init = (pEVP_DigestSignInit_fn)
      dlsym(ossl_handle, "EVP_DigestSignInit");
  ossl_digest_sign = (pEVP_DigestSign_fn)dlsym(ossl_handle, "EVP_DigestSign");
  ossl_digest_verify_init = (pEVP_DigestVerifyInit_fn)
      dlsym(ossl_handle, "EVP_DigestVerifyInit");
  ossl_digest_verify = (pEVP_DigestVerify_fn)
      dlsym(ossl_handle, "EVP_DigestVerify");
  ossl_get_raw_pub = (pEVP_PKEY_get_raw_public_key_fn)
      dlsym(ossl_handle, "EVP_PKEY_get_raw_public_key");
  ossl_err_clear = (pERR_clear_error_fn)dlsym(ossl_handle, "ERR_clear_error");

  if (!ossl_new_raw_priv || !ossl_new_raw_pub || !ossl_md_ctx_new ||
      !ossl_md_ctx_free || !ossl_pkey_free || !ossl_digest_sign_init ||
      !ossl_digest_sign || !ossl_digest_verify_init || !ossl_digest_verify ||
      !ossl_get_raw_pub || !ossl_err_clear) {
    fprintf(stderr, "Failed to resolve OpenSSL symbols: %s\n", dlerror());
    dlclose(ossl_handle);
    ossl_handle = NULL;
    return 0;
  }

  // Determine the NID for Ed448 in this OpenSSL build
  // Try creating a key to verify the NID works
  const uint8_t test_seed[57] = {
      0x6c, 0x82, 0xa5, 0x62, 0xcb, 0x80, 0x8d, 0x10, 0xd6, 0x32, 0xbe,
      0x89, 0xc8, 0x51, 0x3e, 0xbf, 0x6c, 0x92, 0x9f, 0x34, 0xdd, 0xfa,
      0x8c, 0x9f, 0x63, 0xc9, 0x96, 0x0e, 0xf6, 0xe3, 0x48, 0xa3, 0x52,
      0x8c, 0x8a, 0x3f, 0xcc, 0x2f, 0x04, 0x4e, 0x39, 0xa3, 0xfc, 0x5b,
      0x94, 0x49, 0x2f, 0x8f, 0x03, 0x2e, 0x75, 0x49, 0xa2, 0x00, 0x98,
      0xf9, 0x5b
  };
  void *pkey = ossl_new_raw_priv(OSSL_EVP_PKEY_ED448, NULL, test_seed, 57);
  if (!pkey) {
    ossl_err_clear();
    fprintf(stderr, "OpenSSL Ed448 not functional with NID %d\n",
            OSSL_EVP_PKEY_ED448);
    dlclose(ossl_handle);
    ossl_handle = NULL;
    return 0;
  }
  ossl_pkey_free(pkey);
  return 1;
}

void openssl_ed448_cleanup(void) {
  if (ossl_handle) {
    dlclose(ossl_handle);
    ossl_handle = NULL;
  }
}

int openssl_ed448_sign(uint8_t *sig_out, size_t *sig_len_out,
                       const uint8_t *privkey_seed, size_t seed_len,
                       const uint8_t *msg, size_t msg_len) {
  if (!ossl_handle) return 0;

  void *pkey = ossl_new_raw_priv(OSSL_EVP_PKEY_ED448, NULL,
                                  privkey_seed, seed_len);
  if (!pkey) { ossl_err_clear(); return 0; }

  void *md_ctx = ossl_md_ctx_new();
  if (!md_ctx) { ossl_pkey_free(pkey); return 0; }

  int ret = 0;
  if (ossl_digest_sign_init(md_ctx, NULL, NULL, NULL, pkey) != 1) goto done;

  *sig_len_out = 114;
  if (ossl_digest_sign(md_ctx, sig_out, sig_len_out, msg, msg_len) != 1) goto done;
  ret = 1;

done:
  ossl_md_ctx_free(md_ctx);
  ossl_pkey_free(pkey);
  if (!ret) ossl_err_clear();
  return ret;
}

int openssl_ed448_verify(const uint8_t *pubkey, size_t pubkey_len,
                         const uint8_t *msg, size_t msg_len,
                         const uint8_t *sig, size_t sig_len) {
  if (!ossl_handle) return 0;

  void *pkey = ossl_new_raw_pub(OSSL_EVP_PKEY_ED448, NULL, pubkey, pubkey_len);
  if (!pkey) { ossl_err_clear(); return 0; }

  void *md_ctx = ossl_md_ctx_new();
  if (!md_ctx) { ossl_pkey_free(pkey); return 0; }

  int ret = 0;
  if (ossl_digest_verify_init(md_ctx, NULL, NULL, NULL, pkey) != 1) goto done;
  ret = (ossl_digest_verify(md_ctx, sig, sig_len, msg, msg_len) == 1) ? 1 : 0;

done:
  ossl_md_ctx_free(md_ctx);
  ossl_pkey_free(pkey);
  ossl_err_clear();
  return ret;
}

int openssl_ed448_pubkey_from_seed(uint8_t *pubkey_out, size_t *pubkey_len_out,
                                   const uint8_t *seed, size_t seed_len) {
  if (!ossl_handle) return 0;

  void *pkey = ossl_new_raw_priv(OSSL_EVP_PKEY_ED448, NULL, seed, seed_len);
  if (!pkey) { ossl_err_clear(); return 0; }

  *pubkey_len_out = 57;
  int ret = ossl_get_raw_pub(pkey, pubkey_out, pubkey_len_out);
  ossl_pkey_free(pkey);
  if (!ret) ossl_err_clear();
  return ret;
}
