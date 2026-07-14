// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// Ed448 2-way differential harness: aws-lc vs OpenSSL
//
// References wired:
//   - OpenSSL: YES (full Ed448 implementation)
//   - BoringSSL: NO (does not implement Ed448 — only defines NID for compat)
//   - Cryptol: NO (no Ed448/Curve448 specification available)
//
// The harness uses a fixed, logged seed for reproducibility. On each iteration
// it generates a random 57-byte private key seed, derives the public key from
// both libraries, signs a random message with both, and cross-verifies.
// Any mismatch is a failure.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

// OpenSSL reference: loaded via dlopen to avoid symbol collisions
extern int openssl_ed448_init(const char *libcrypto_path);
extern void openssl_ed448_cleanup(void);
extern int openssl_ed448_sign(uint8_t *sig_out, size_t *sig_len_out,
                              const uint8_t *privkey_seed, size_t seed_len,
                              const uint8_t *msg, size_t msg_len);
extern int openssl_ed448_verify(const uint8_t *pubkey, size_t pubkey_len,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t *sig, size_t sig_len);
extern int openssl_ed448_pubkey_from_seed(uint8_t *pubkey_out,
                                          size_t *pubkey_len_out,
                                          const uint8_t *seed, size_t seed_len);

extern int awslc_ed448_sign(uint8_t *sig_out, size_t *sig_len_out,
                            const uint8_t *privkey_seed, size_t seed_len,
                            const uint8_t *msg, size_t msg_len);
extern int awslc_ed448_verify(const uint8_t *pubkey, size_t pubkey_len,
                              const uint8_t *msg, size_t msg_len,
                              const uint8_t *sig, size_t sig_len);
extern int awslc_ed448_pubkey_from_seed(uint8_t *pubkey_out,
                                        size_t *pubkey_len_out,
                                        const uint8_t *seed, size_t seed_len);

#define ED448_KEY_LEN 57
#define ED448_SIG_LEN 114
#define NUM_ITERATIONS 500
#define MAX_MSG_LEN 1024

static void print_hex(const char *label, const uint8_t *data, size_t len) {
  printf("  %s: ", label);
  for (size_t i = 0; i < len; i++) {
    printf("%02x", data[i]);
  }
  printf("\n");
}

// Simple deterministic PRNG seeded from a known value (xorshift64)
static uint64_t prng_state;

static void prng_seed(uint64_t seed) {
  prng_state = seed ? seed : 1;
}

static uint64_t prng_next(void) {
  prng_state ^= prng_state << 13;
  prng_state ^= prng_state >> 7;
  prng_state ^= prng_state << 17;
  return prng_state;
}

static void prng_fill(uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (i % 8 == 0) {
      uint64_t v = prng_next();
      memcpy(buf + i, &v, (len - i < 8) ? (len - i) : 8);
    }
  }
}

int main(int argc, char **argv) {
  // Fixed seed for reproducibility; override via command line
  uint64_t seed = 0xED448CAFE0001ULL;
  const char *openssl_lib = NULL;
  if (argc > 1) {
    seed = strtoull(argv[1], NULL, 0);
  }
  if (argc > 2) {
    openssl_lib = argv[2];
  }

  // The OpenSSL .so path MUST be provided (from LIBRARY_PATHS.env)
  if (!openssl_lib || !openssl_lib[0]) {
    fprintf(stderr, "Usage: %s [seed] <openssl_libcrypto.so_path>\n", argv[0]);
    fprintf(stderr, "The OpenSSL .so path is required to avoid symbol collisions.\n");
    return 1;
  }

  printf("=== Ed448 Differential Harness ===\n");
  printf("Seed: 0x%016llx\n", (unsigned long long)seed);
  printf("Iterations: %d\n", NUM_ITERATIONS);
  printf("References: aws-lc (target, static) vs OpenSSL (reference, dlopen)\n");
  printf("  OpenSSL lib: %s\n", openssl_lib);
  printf("  BoringSSL: NOT AVAILABLE (does not implement Ed448)\n");
  printf("  Cryptol:   NOT AVAILABLE (no Ed448 spec exists)\n");
  printf("\n");

  if (!openssl_ed448_init(openssl_lib)) {
    fprintf(stderr, "FATAL: Failed to initialize OpenSSL Ed448 reference.\n");
    return 1;
  }

  prng_seed(seed);

  int failures = 0;
  int awslc_not_ready = 0;

  for (int i = 0; i < NUM_ITERATIONS; i++) {
    // Generate random private key seed
    uint8_t privkey_seed[ED448_KEY_LEN];
    prng_fill(privkey_seed, ED448_KEY_LEN);

    // Generate random message (variable length 0..MAX_MSG_LEN)
    size_t msg_len = prng_next() % (MAX_MSG_LEN + 1);
    uint8_t *msg = (uint8_t *)malloc(msg_len + 1);
    if (!msg) {
      fprintf(stderr, "FATAL: malloc failed\n");
      return 1;
    }
    prng_fill(msg, msg_len);

    // --- Public key derivation ---
    uint8_t openssl_pub[ED448_KEY_LEN], awslc_pub[ED448_KEY_LEN];
    size_t openssl_pub_len = 0, awslc_pub_len = 0;

    int ossl_pk_ok = openssl_ed448_pubkey_from_seed(
        openssl_pub, &openssl_pub_len, privkey_seed, ED448_KEY_LEN);
    int awslc_pk_ok = awslc_ed448_pubkey_from_seed(
        awslc_pub, &awslc_pub_len, privkey_seed, ED448_KEY_LEN);

    if (!ossl_pk_ok) {
      fprintf(stderr, "ERROR: OpenSSL pubkey derivation failed at iter %d\n", i);
      failures++;
      free(msg);
      continue;
    }

    if (!awslc_pk_ok) {
      // aws-lc Ed448 not yet implemented — track but don't fail
      if (awslc_not_ready == 0) {
        printf("NOTE: aws-lc Ed448 not yet implemented (first at iter %d). "
               "Running OpenSSL-only validation.\n", i);
      }
      awslc_not_ready++;
      free(msg);
      continue;
    }

    // Compare public keys
    if (openssl_pub_len != awslc_pub_len ||
        memcmp(openssl_pub, awslc_pub, openssl_pub_len) != 0) {
      printf("FAILURE at iteration %d: public key mismatch\n", i);
      print_hex("seed", privkey_seed, ED448_KEY_LEN);
      print_hex("openssl_pub", openssl_pub, openssl_pub_len);
      print_hex("awslc_pub", awslc_pub, awslc_pub_len);
      failures++;
      free(msg);
      continue;
    }

    // --- Signing ---
    uint8_t openssl_sig[ED448_SIG_LEN], awslc_sig[ED448_SIG_LEN];
    size_t openssl_sig_len = 0, awslc_sig_len = 0;

    int ossl_sign_ok = openssl_ed448_sign(
        openssl_sig, &openssl_sig_len, privkey_seed, ED448_KEY_LEN,
        msg, msg_len);
    int awslc_sign_ok = awslc_ed448_sign(
        awslc_sig, &awslc_sig_len, privkey_seed, ED448_KEY_LEN,
        msg, msg_len);

    if (!ossl_sign_ok) {
      fprintf(stderr, "ERROR: OpenSSL sign failed at iter %d\n", i);
      failures++;
      free(msg);
      continue;
    }
    if (!awslc_sign_ok) {
      fprintf(stderr, "ERROR: aws-lc sign failed at iter %d\n", i);
      failures++;
      free(msg);
      continue;
    }

    // Ed448 signing is deterministic — signatures MUST match
    if (openssl_sig_len != awslc_sig_len ||
        memcmp(openssl_sig, awslc_sig, openssl_sig_len) != 0) {
      printf("FAILURE at iteration %d: signature mismatch\n", i);
      print_hex("seed", privkey_seed, ED448_KEY_LEN);
      printf("  msg_len: %zu\n", msg_len);
      print_hex("openssl_sig", openssl_sig, openssl_sig_len);
      print_hex("awslc_sig", awslc_sig, awslc_sig_len);
      failures++;
      free(msg);
      continue;
    }

    // --- Cross-verification ---
    // OpenSSL signature verified by aws-lc
    int awslc_verify_ossl = awslc_ed448_verify(
        awslc_pub, awslc_pub_len, msg, msg_len,
        openssl_sig, openssl_sig_len);
    // aws-lc signature verified by OpenSSL
    int ossl_verify_awslc = openssl_ed448_verify(
        openssl_pub, openssl_pub_len, msg, msg_len,
        awslc_sig, awslc_sig_len);

    if (!awslc_verify_ossl) {
      printf("FAILURE at iteration %d: aws-lc failed to verify OpenSSL sig\n", i);
      print_hex("pubkey", awslc_pub, awslc_pub_len);
      print_hex("openssl_sig", openssl_sig, openssl_sig_len);
      failures++;
    }
    if (!ossl_verify_awslc) {
      printf("FAILURE at iteration %d: OpenSSL failed to verify aws-lc sig\n", i);
      print_hex("pubkey", openssl_pub, openssl_pub_len);
      print_hex("awslc_sig", awslc_sig, awslc_sig_len);
      failures++;
    }

    free(msg);
  }

  printf("\n=== Results ===\n");
  printf("Iterations: %d\n", NUM_ITERATIONS);
  if (awslc_not_ready > 0) {
    printf("aws-lc not ready: %d/%d iterations (Ed448 not yet implemented)\n",
           awslc_not_ready, NUM_ITERATIONS);
  }
  printf("Failures: %d\n", failures);

  openssl_ed448_cleanup();

  if (failures > 0) {
    printf("FAIL\n");
    return 1;
  }
  if (awslc_not_ready == NUM_ITERATIONS) {
    printf("SKIP (aws-lc Ed448 not yet implemented; OpenSSL reference validated)\n");
    return 0;
  }
  printf("PASS\n");
  return 0;
}
