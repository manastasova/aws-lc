// Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include <new>
#include <vector>

#include <gtest/gtest.h>

#include <openssl/aes.h>

#include "../../internal.h"
#include "../../test/abi_test.h"
#include "../../test/file_test.h"
#include "../../test/test_util.h"
#include "../aes/internal.h"
#include "../cpucap/internal.h"
#include "internal.h"


TEST(GCMTest, TestVectors) {
  FileTestGTest("crypto/fipsmodule/modes/gcm_tests.txt", [](FileTest *t) {
    std::vector<uint8_t> key, plaintext, additional_data, nonce, ciphertext,
        tag;
    ASSERT_TRUE(t->GetBytes(&key, "Key"));
    ASSERT_TRUE(t->GetBytes(&plaintext, "Plaintext"));
    ASSERT_TRUE(t->GetBytes(&additional_data, "AdditionalData"));
    ASSERT_TRUE(t->GetBytes(&nonce, "Nonce"));
    ASSERT_TRUE(t->GetBytes(&ciphertext, "Ciphertext"));
    ASSERT_TRUE(t->GetBytes(&tag, "Tag"));

    ASSERT_EQ(plaintext.size(), ciphertext.size());
    ASSERT_TRUE(key.size() == 16 || key.size() == 24 || key.size() == 32);
    ASSERT_EQ(16u, tag.size());

    std::vector<uint8_t> out(plaintext.size());
    AES_KEY aes_key;
    ASSERT_EQ(0, AES_set_encrypt_key(key.data(), key.size() * 8, &aes_key));

    GCM128_CONTEXT ctx;
    OPENSSL_memset(&ctx, 0, sizeof(ctx));
    CRYPTO_gcm128_init_key(&ctx.gcm_key, &aes_key, AES_encrypt, 0);
    CRYPTO_gcm128_setiv(&ctx, &aes_key, nonce.data(), nonce.size());
    if (!additional_data.empty()) {
      CRYPTO_gcm128_aad(&ctx, additional_data.data(), additional_data.size());
    }
    if (!plaintext.empty()) {
      CRYPTO_gcm128_encrypt(&ctx, &aes_key, plaintext.data(), out.data(),
                            plaintext.size());
    }

    std::vector<uint8_t> got_tag(tag.size());
    CRYPTO_gcm128_tag(&ctx, got_tag.data(), got_tag.size());
    EXPECT_EQ(Bytes(tag), Bytes(got_tag));
    EXPECT_EQ(Bytes(ciphertext), Bytes(out));

    CRYPTO_gcm128_setiv(&ctx, &aes_key, nonce.data(), nonce.size());
    OPENSSL_memset(out.data(), 0, out.size());
    if (!additional_data.empty()) {
      CRYPTO_gcm128_aad(&ctx, additional_data.data(), additional_data.size());
    }
    if (!ciphertext.empty()) {
      CRYPTO_gcm128_decrypt(&ctx, &aes_key, ciphertext.data(), out.data(),
                            ciphertext.size());
    }
    ASSERT_TRUE(CRYPTO_gcm128_finish(&ctx, tag.data(), tag.size()));
    EXPECT_EQ(Bytes(plaintext), Bytes(out));
  });
}

TEST(GCMTest, ByteSwap) {
  EXPECT_EQ(0x04030201u, CRYPTO_bswap4(0x01020304u));
  EXPECT_EQ(UINT64_C(0x0807060504030201),
            CRYPTO_bswap8(UINT64_C(0x0102030405060708)));
}

#if defined(SUPPORTS_ABI_TEST) && !defined(OPENSSL_NO_ASM) && \
    !defined(MY_ASSEMBLER_IS_TOO_OLD_FOR_AVX)
TEST(GCMTest, ABI) {
  static const uint64_t kH[2] = {
      UINT64_C(0x66e94bd4ef8a2c3b),
      UINT64_C(0x884cfa59ca342b2e),
  };
  static const size_t kBlockCounts[] = {1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 31, 32};
  uint8_t buf[16 * 32];
  OPENSSL_memset(buf, 42, sizeof(buf));

  alignas(16) uint8_t X[16] = {0x92, 0xa3, 0xb3, 0x60, 0xce, 0xda, 0x88, 0x03,
                   0x78, 0xfe, 0xb2, 0x71, 0xb9, 0xc2, 0x28, 0xf3};

  alignas(16) u128 Htable[16];
#if defined(GHASH_ASM_X86) || defined(GHASH_ASM_X86_64)
  if (CRYPTO_is_SSSE3_capable()) {
    CHECK_ABI_SEH(gcm_init_ssse3, Htable, kH);
    CHECK_ABI_SEH(gcm_gmult_ssse3, X, Htable);
    for (size_t blocks : kBlockCounts) {
      CHECK_ABI_SEH(gcm_ghash_ssse3, X, Htable, buf, 16 * blocks);
    }
  }

  if (crypto_gcm_clmul_enabled()) {
    CHECK_ABI_SEH(gcm_init_clmul, Htable, kH);
    CHECK_ABI_SEH(gcm_gmult_clmul, X, Htable);
    for (size_t blocks : kBlockCounts) {
      CHECK_ABI_SEH(gcm_ghash_clmul, X, Htable, buf, 16 * blocks);
    }

#if defined(GHASH_ASM_X86_64)
    if (CRYPTO_is_AVX_capable() && CRYPTO_is_MOVBE_capable()) {
      CHECK_ABI_SEH(gcm_init_avx, Htable, kH);
      CHECK_ABI_SEH(gcm_gmult_avx, X, Htable);
      for (size_t blocks : kBlockCounts) {
        CHECK_ABI_SEH(gcm_ghash_avx, X, Htable, buf, 16 * blocks);
      }

      if (hwaes_capable()) {
        AES_KEY aes_key;
        static const uint8_t kKey[16] = {0};
        uint8_t iv[16] = {0};

        aes_hw_set_encrypt_key(kKey, 128, &aes_key);
        for (size_t blocks : kBlockCounts) {
          CHECK_ABI_SEH(aesni_gcm_encrypt, buf, buf, blocks * 16, &aes_key, iv,
                        Htable, X);
          CHECK_ABI_SEH(aesni_gcm_encrypt, buf, buf, blocks * 16 + 7, &aes_key,
                        iv, Htable, X);
        }
        aes_hw_set_decrypt_key(kKey, 128, &aes_key);
        for (size_t blocks : kBlockCounts) {
          CHECK_ABI_SEH(aesni_gcm_decrypt, buf, buf, blocks * 16, &aes_key, iv,
                        Htable, X);
          CHECK_ABI_SEH(aesni_gcm_decrypt, buf, buf, blocks * 16 + 7, &aes_key,
                        iv, Htable, X);
        }
      }
    }
#if !defined(MY_ASSEMBLER_IS_TOO_OLD_FOR_512AVX)
    if (crypto_gcm_avx512_enabled()) {
      CHECK_ABI_SEH(gcm_init_avx512, Htable, kH);
      CHECK_ABI_SEH(gcm_gmult_avx512, X, Htable);
      for (size_t blocks : kBlockCounts) {
        CHECK_ABI_SEH(gcm_ghash_avx512, X, Htable, buf, 16 * blocks);
      }

      if (hwaes_capable()) {
        AES_KEY aes_key;
        static const uint8_t kKey[16] = {0};

        // aes_gcm_*_avx512 makes assumptions about |GCM128_CONTEXT|'s layout.
        GCM128_CONTEXT gcm;
        memset(&gcm, 0, sizeof(gcm));
        memcpy(&gcm.gcm_key.Htable, Htable, sizeof(Htable));
        memcpy(&gcm.Xi, X, sizeof(X));
        uint8_t iv[16] = {0};

        aes_hw_set_encrypt_key(kKey, 128, &aes_key);

        CHECK_ABI_SEH(gcm_setiv_avx512, &aes_key, &gcm, iv, sizeof(iv));

        for (size_t blocks : kBlockCounts) {
          CHECK_ABI_SEH(aes_gcm_encrypt_avx512, &aes_key, &gcm, &gcm.mres, buf,
                        blocks * 16, buf);
        }
        aes_hw_set_decrypt_key(kKey, 128, &aes_key);
        for (size_t blocks : kBlockCounts) {
          CHECK_ABI_SEH(aes_gcm_decrypt_avx512, &aes_key, &gcm, &gcm.mres, buf,
                        blocks * 16, buf);
        }
      }
    }
#endif // !MY_ASSEMBLER_IS_TOO_OLD_FOR_512AVX)
#endif  // GHASH_ASM_X86_64
  }
#endif  // GHASH_ASM_X86 || GHASH_ASM_X86_64

#if defined(GHASH_ASM_ARM)
  if (gcm_neon_capable()) {
    CHECK_ABI(gcm_init_neon, Htable, kH);
    CHECK_ABI(gcm_gmult_neon, X, Htable);
    for (size_t blocks : kBlockCounts) {
      CHECK_ABI(gcm_ghash_neon, X, Htable, buf, 16 * blocks);
    }
  }

  if (gcm_pmull_capable()) {
    CHECK_ABI(gcm_init_v8, Htable, kH);
    CHECK_ABI(gcm_gmult_v8, X, Htable);
    for (size_t blocks : kBlockCounts) {
      CHECK_ABI(gcm_ghash_v8, X, Htable, buf, 16 * blocks);
    }
  }
#endif  // GHASH_ASM_ARM

#if defined(OPENSSL_AARCH64) && defined(HW_GCM)
  if (hwaes_capable() && gcm_pmull_capable()) {
    static const uint8_t kKey[256 / 8] = {0};
    uint8_t iv[16] = {0};
    uint8_t out[sizeof(buf)];
    alignas(16) AES_KEY aes_key;
    const s2n_bignum_AES_KEY *s2n_key =
        reinterpret_cast<const s2n_bignum_AES_KEY *>(&aes_key);
    uint64_t *tag = reinterpret_cast<uint64_t *>(X);
    const uint64_t *htable = reinterpret_cast<const uint64_t *>(Htable);
    for (size_t blocks : kBlockCounts) {
      aes_hw_set_encrypt_key(kKey, 128, &aes_key);
      CHECK_ABI(aes128_gcm_enc, buf, blocks * 128, out, tag, iv, s2n_key,
                htable);
      CHECK_ABI(aes128_gcm_dec, buf, blocks * 128, out, tag, iv, s2n_key,
                htable);
      aes_hw_set_encrypt_key(kKey, 256, &aes_key);
      CHECK_ABI(aes256_gcm_enc, buf, blocks * 128, out, tag, iv, s2n_key,
                htable);
      CHECK_ABI(aes256_gcm_dec, buf, blocks * 128, out, tag, iv, s2n_key,
                htable);
      if (CRYPTO_is_ARMv8_SHA3_capable()) {
        aes_hw_set_encrypt_key(kKey, 128, &aes_key);
        CHECK_ABI(aes128_gcm_enc_alt, buf, blocks * 128, out, tag, iv, s2n_key,
                  htable);
        CHECK_ABI(aes128_gcm_dec_alt, buf, blocks * 128, out, tag, iv, s2n_key,
                  htable);
        aes_hw_set_encrypt_key(kKey, 256, &aes_key);
        CHECK_ABI(aes256_gcm_enc_alt, buf, blocks * 128, out, tag, iv, s2n_key,
                  htable);
        CHECK_ABI(aes256_gcm_dec_alt, buf, blocks * 128, out, tag, iv, s2n_key,
                  htable);
      }
    }
  }

#endif

#if defined(GHASH_ASM_PPC64LE)
  if (CRYPTO_is_PPC64LE_vcrypto_capable()) {
    CHECK_ABI(gcm_init_p8, Htable, kH);
    CHECK_ABI(gcm_gmult_p8, X, Htable);
    for (size_t blocks : kBlockCounts) {
      CHECK_ABI(gcm_ghash_p8, X, Htable, buf, 16 * blocks);
    }
  }
#endif  // GHASH_ASM_PPC64LE
}
#endif  // SUPPORTS_ABI_TEST && !OPENSSL_NO_ASM && !MY_ASSEMBLER_IS_TOO_OLD_FOR_AVX

#if defined(OPENSSL_AARCH64) && defined(HW_GCM)
// Compare the imported whole-block path, its scalar remainder, and its
// in-place/AES-192 fallbacks with the independent generic GCM path.
TEST(GCMTest, Ctr32Hardware) {
  if (!hwaes_capable() || !gcm_pmull_capable()) {
    GTEST_SKIP();
  }
  static const size_t kLengths[] = {0,    1,    15,   16,   17,   31,   32,
                                   33,   63,   64,   65,   127,  128,  129,
                                   255,  256,  257,  511,  512,  513,  1023,
                                   1024, 1025, 4095, 4096, 4097};
  static const uint32_t kCounters[] = {2, UINT32_MAX - 7, UINT32_MAX};
  uint8_t key_bytes[32], nonce[12], aad[23];
  for (size_t i = 0; i < sizeof(key_bytes); i++) {
    key_bytes[i] = static_cast<uint8_t>(13 * i + 1);
  }
  for (size_t i = 0; i < sizeof(nonce); i++) {
    nonce[i] = static_cast<uint8_t>(7 * i + 2);
  }
  for (size_t i = 0; i < sizeof(aad); i++) {
    aad[i] = static_cast<uint8_t>(3 * i + 5);
  }

  for (unsigned key_bits : {128u, 192u, 256u}) {
    // AES_KEY needs four-byte alignment. Its public low-level API also accepts
    // the second position here, which is not aligned for s2n_bignum_AES_KEY.
    for (size_t key_offset : {size_t{0}, size_t{4}}) {
      alignas(16) uint8_t key_storage[sizeof(AES_KEY) + 8];
      AES_KEY *key = new (key_storage + key_offset) AES_KEY;
      ASSERT_EQ(0, aes_hw_set_encrypt_key(key_bytes, key_bits, key));
      for (size_t len : kLengths) {
        std::vector<uint8_t> plaintext(len + 1, 0xa5);
        for (size_t i = 0; i < len; i++) {
          plaintext[i] = static_cast<uint8_t>(17 * i + 3);
        }
        for (uint32_t counter : kCounters) {
          auto init_context = [&](GCM128_CONTEXT *ctx) {
            OPENSSL_memset(ctx, 0, sizeof(*ctx));
            CRYPTO_gcm128_init_key(&ctx->gcm_key, key, aes_hw_encrypt, 1);
            CRYPTO_gcm128_setiv(ctx, key, nonce, sizeof(nonce));
            CRYPTO_store_u32_be(ctx->Yi + 12, counter);
            ASSERT_TRUE(CRYPTO_gcm128_aad(ctx, aad, sizeof(aad)));
          };
          GCM128_CONTEXT reference;
          init_context(&reference);
          std::vector<uint8_t> ciphertext(len + 1, 0xa5);
          ASSERT_TRUE(CRYPTO_gcm128_encrypt(&reference, key, plaintext.data(),
                                            ciphertext.data(), len));
          uint8_t expected_tag[16];
          CRYPTO_gcm128_tag(&reference, expected_tag, sizeof(expected_tag));

          for (bool decrypt : {false, true}) {
            const auto &input = decrypt ? ciphertext : plaintext;
            const auto &expected = decrypt ? plaintext : ciphertext;
            for (bool in_place : {false, true}) {
              for (bool split_update : {false, true}) {
                SCOPED_TRACE(::testing::Message()
                             << "key_bits=" << key_bits
                             << " key_offset=" << key_offset << " len=" << len
                             << " counter=" << counter << " decrypt=" << decrypt
                             << " in_place=" << in_place
                             << " split_update=" << split_update);
                GCM128_CONTEXT actual;
                init_context(&actual);
                std::vector<uint8_t> out =
                    in_place ? input : std::vector<uint8_t>(len + 1, 0xa5);
                const uint8_t *in = in_place ? out.data() : input.data();
                const size_t first = split_update && len > 17 ? 17 : len;
                auto update = [&](size_t offset, size_t length) {
                  return decrypt
                             ? CRYPTO_gcm128_decrypt_ctr32(
                                   &actual, key, in + offset, out.data() + offset,
                                   length, aes_hw_ctr32_encrypt_blocks)
                             : CRYPTO_gcm128_encrypt_ctr32(
                                   &actual, key, in + offset, out.data() + offset,
                                   length, aes_hw_ctr32_encrypt_blocks);
                };
                ASSERT_TRUE(update(0, first));
                if (first != len) {
                  ASSERT_TRUE(update(first, len - first));
                }
                uint8_t actual_tag[16];
                CRYPTO_gcm128_tag(&actual, actual_tag, sizeof(actual_tag));
                EXPECT_EQ(Bytes(expected), Bytes(out));
                EXPECT_EQ(Bytes(expected_tag), Bytes(actual_tag));
                EXPECT_EQ(Bytes(reference.Yi), Bytes(actual.Yi));
              }
            }
          }
        }
      }
    }
  }
}
#endif  // OPENSSL_AARCH64 && HW_GCM
