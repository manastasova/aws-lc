// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <openssl/evp.h>

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "../fipsmodule/evp/internal.h"
#include "../internal.h"
#include "internal.h"
#include "../curve448/internal.h"


static void ed448_free(EVP_PKEY *pkey) {
  ED448_KEY *key = pkey->pkey.ptr;
  if (key != NULL) {
    OPENSSL_cleanse(key, sizeof(ED448_KEY));
    OPENSSL_free(key);
  }
  pkey->pkey.ptr = NULL;
}

static int ed448_set_priv_raw(EVP_PKEY *pkey, const uint8_t *privkey,
                              size_t privkey_len, const uint8_t *pubkey,
                              size_t pubkey_len) {
  if (privkey_len != ED448_SEED_LEN) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return 0;
  }

  if (pubkey && pubkey_len != ED448_PUBLIC_KEY_LEN) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return 0;
  }

  ED448_KEY *key = OPENSSL_malloc(sizeof(ED448_KEY));
  if (key == NULL) {
    return 0;
  }

  uint8_t pubkey_computed[ED448_PUBLIC_KEY_LEN];
  uint8_t priv_unused[ED448_SEED_LEN];
  ED448_keypair_from_seed(pubkey_computed, priv_unused, privkey);
  OPENSSL_memcpy(key->seed, privkey, ED448_SEED_LEN);
  OPENSSL_memcpy(key->pub, pubkey_computed, ED448_PUBLIC_KEY_LEN);
  key->has_private = 1;

  if (pubkey && OPENSSL_memcmp(pubkey_computed, pubkey, pubkey_len) != 0) {
    OPENSSL_cleanse(key, sizeof(ED448_KEY));
    OPENSSL_free(key);
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return 0;
  }

  OPENSSL_cleanse(priv_unused, sizeof(priv_unused));
  ed448_free(pkey);
  pkey->pkey.ptr = key;
  return 1;
}

static int ed448_set_pub_raw(EVP_PKEY *pkey, const uint8_t *in, size_t len) {
  if (len != ED448_PUBLIC_KEY_LEN) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return 0;
  }

  ED448_KEY *key = OPENSSL_malloc(sizeof(ED448_KEY));
  if (key == NULL) {
    return 0;
  }

  OPENSSL_memcpy(key->pub, in, ED448_PUBLIC_KEY_LEN);
  OPENSSL_memset(key->seed, 0, ED448_SEED_LEN);
  key->has_private = 0;

  ed448_free(pkey);
  pkey->pkey.ptr = key;
  return 1;
}

static int ed448_get_priv_raw(const EVP_PKEY *pkey, uint8_t *out,
                              size_t *out_len) {
  const ED448_KEY *key = pkey->pkey.ptr;
  if (!key->has_private) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NOT_A_PRIVATE_KEY);
    return 0;
  }

  if (out == NULL) {
    *out_len = ED448_SEED_LEN;
    return 1;
  }

  if (*out_len < ED448_SEED_LEN) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_BUFFER_TOO_SMALL);
    return 0;
  }

  OPENSSL_memcpy(out, key->seed, ED448_SEED_LEN);
  *out_len = ED448_SEED_LEN;
  return 1;
}

static int ed448_get_pub_raw(const EVP_PKEY *pkey, uint8_t *out,
                             size_t *out_len) {
  const ED448_KEY *key = pkey->pkey.ptr;
  if (out == NULL) {
    *out_len = ED448_PUBLIC_KEY_LEN;
    return 1;
  }

  if (*out_len < ED448_PUBLIC_KEY_LEN) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_BUFFER_TOO_SMALL);
    return 0;
  }

  OPENSSL_memcpy(out, key->pub, ED448_PUBLIC_KEY_LEN);
  *out_len = ED448_PUBLIC_KEY_LEN;
  return 1;
}

static int ed448_pub_decode(EVP_PKEY *out, CBS *oid, CBS *params, CBS *key) {
  if (CBS_len(params) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return 0;
  }

  return ed448_set_pub_raw(out, CBS_data(key), CBS_len(key));
}

static int ed448_pub_encode(CBB *out, const EVP_PKEY *pkey) {
  const ED448_KEY *key = pkey->pkey.ptr;

  CBB spki, algorithm, oid, key_bitstring;
  if (!CBB_add_asn1(out, &spki, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&spki, &algorithm, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&algorithm, &oid, CBS_ASN1_OBJECT) ||
      !CBB_add_bytes(&oid, ed448_asn1_meth.oid, ed448_asn1_meth.oid_len) ||
      !CBB_add_asn1(&spki, &key_bitstring, CBS_ASN1_BITSTRING) ||
      !CBB_add_u8(&key_bitstring, 0 /* padding */) ||
      !CBB_add_bytes(&key_bitstring, key->pub, ED448_PUBLIC_KEY_LEN) ||
      !CBB_flush(out)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);
    return 0;
  }

  return 1;
}

static int ed448_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b) {
  const ED448_KEY *a_key = a->pkey.ptr;
  const ED448_KEY *b_key = b->pkey.ptr;
  return OPENSSL_memcmp(a_key->pub, b_key->pub, ED448_PUBLIC_KEY_LEN) == 0;
}

static int ed448_priv_decode(EVP_PKEY *out, CBS *oid, CBS *params,
                             CBS *key, CBS *pubkey) {
  CBS inner;
  if (CBS_len(params) != 0 ||
      !CBS_get_asn1(key, &inner, CBS_ASN1_OCTETSTRING) ||
      CBS_len(key) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return 0;
  }

  const uint8_t *pub = NULL;
  size_t pub_len = 0;
  if (pubkey) {
    uint8_t padding;
    if (!CBS_get_u8(pubkey, &padding) || padding != 0) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
      return 0;
    }
    pub = CBS_data(pubkey);
    pub_len = CBS_len(pubkey);
  }

  return ed448_set_priv_raw(out, CBS_data(&inner), CBS_len(&inner), pub,
                            pub_len);
}

static int ed448_priv_encode(CBB *out, const EVP_PKEY *pkey) {
  ED448_KEY *key = pkey->pkey.ptr;
  if (!key->has_private) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NOT_A_PRIVATE_KEY);
    return 0;
  }

  CBB pkcs8, algorithm, oid, private_key, inner;
  if (!CBB_add_asn1(out, &pkcs8, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1_uint64(&pkcs8, PKCS8_VERSION_ONE) ||
      !CBB_add_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&algorithm, &oid, CBS_ASN1_OBJECT) ||
      !CBB_add_bytes(&oid, ed448_asn1_meth.oid, ed448_asn1_meth.oid_len) ||
      !CBB_add_asn1(&pkcs8, &private_key, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_asn1(&private_key, &inner, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_bytes(&inner, key->seed, ED448_SEED_LEN) ||
      !CBB_flush(out)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);
    return 0;
  }

  return 1;
}

static int ed448_size(const EVP_PKEY *pkey) { return ED448_SIGNATURE_LEN; }

static int ed448_bits(const EVP_PKEY *pkey) { return 448; }

const EVP_PKEY_ASN1_METHOD ed448_asn1_meth = {
    EVP_PKEY_ED448,
    // OID 1.3.101.113 = 0x2b 0x65 0x71
    {0x2b, 0x65, 0x71},
    3,
    "ED448",
    "OpenSSL ED448 algorithm",
    ed448_pub_decode,
    ed448_pub_encode,
    ed448_pub_cmp,
    ed448_priv_decode,
    ed448_priv_encode,
    NULL /* priv_encode_v2 */,
    ed448_set_priv_raw,
    ed448_set_pub_raw,
    ed448_get_priv_raw,
    ed448_get_pub_raw,
    NULL /* get_priv_seed */,
    NULL /* pkey_opaque */,
    ed448_size,
    ed448_bits,
    NULL /* param_missing */,
    NULL /* param_copy */,
    NULL /* param_cmp */,
    ed448_free,
};
