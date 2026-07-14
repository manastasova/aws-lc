# Ed448 Differential Test Harness — Makefile
#
# Links each reference library by FULL ABSOLUTE PATH from LIBRARY_PATHS.env.
# Each translation unit compiles against its OWN library's headers only.
# This prevents accidental same-library-vs-same-library comparisons.
#
# Usage:
#   source ../../../orchestrator/state/LIBRARY_PATHS.env  (or set vars manually)
#   make
#   ./ed448_diff_test
#
# References wired:
#   - OpenSSL: YES
#   - BoringSSL: NO (does not implement Ed448)
#   - Cryptol: NO (no spec available)

# Source the environment file
ENVFILE := $(shell realpath ../../../../orchestrator/state/LIBRARY_PATHS.env)

# Absolute paths — MUST be set from LIBRARY_PATHS.env, never guessed
AWSLC_LIBCRYPTO ?= $(error Set AWSLC_LIBCRYPTO from LIBRARY_PATHS.env)
AWSLC_INCLUDE ?= $(error Set AWSLC_INCLUDE from LIBRARY_PATHS.env)
OPENSSL_LIBCRYPTO ?= $(error Set OPENSSL_LIBCRYPTO from LIBRARY_PATHS.env)
OPENSSL_INCLUDE ?= $(error Set OPENSSL_INCLUDE from LIBRARY_PATHS.env)

CC ?= gcc
CFLAGS := -Wall -Wextra -O2 -g

# Build targets
.PHONY: all clean check

all: ed448_diff_test

# Each .o compiled against its OWN library's headers
openssl_ref.o: openssl_ref.c
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -c -o $@ $<

awslc_ref.o: awslc_ref.c
	$(CC) $(CFLAGS) -I$(AWSLC_INCLUDE) -c -o $@ $<

ed448_diff_harness.o: ed448_diff_harness.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Link by absolute path — never -lcrypto
ed448_diff_test: ed448_diff_harness.o awslc_ref.o openssl_ref.o
	$(CC) $(CFLAGS) -o $@ $^ \
		$(AWSLC_LIBCRYPTO) $(OPENSSL_LIBCRYPTO) \
		-lpthread -ldl -lm

check: ed448_diff_test
	./ed448_diff_test

clean:
	rm -f *.o ed448_diff_test
