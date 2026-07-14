#!/bin/bash
# Ed448 Differential Harness — Build and Run Script
#
# Compiles the 2-way differential harness (aws-lc vs OpenSSL).
# aws-lc is statically linked; OpenSSL is loaded at runtime via dlopen
# to avoid symbol collisions (both export EVP_PKEY_new_raw_private_key, etc.).
#
# Usage: ./run_diff_test.sh [optional_prng_seed]
#
# References:
#   OpenSSL: YES (loaded via dlopen from absolute path)
#   BoringSSL: NOT AVAILABLE (does not implement Ed448)
#   Cryptol: NOT AVAILABLE (no spec available)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ENV_FILE="$REPO_ROOT/orchestrator/state/LIBRARY_PATHS.env"

echo "=== Ed448 Differential Test Harness ==="
echo "Loading library paths from: $ENV_FILE"

if [ ! -f "$ENV_FILE" ]; then
    echo "ERROR: LIBRARY_PATHS.env not found at $ENV_FILE"
    echo "Run setup.sh first to generate library paths."
    exit 1
fi

# Source the paths
source "$ENV_FILE"

# Find the OpenSSL .so (for dlopen)
OPENSSL_LIBCRYPTO_SO="${OPENSSL_LIBCRYPTO%.a}.so"
if [ ! -f "$OPENSSL_LIBCRYPTO_SO" ]; then
    # Try .so without stripping .a
    OPENSSL_DIR="$(dirname "$OPENSSL_LIBCRYPTO")"
    OPENSSL_LIBCRYPTO_SO="$(find "$OPENSSL_DIR" -name 'libcrypto.so' -o -name 'libcrypto.so.*' | head -1)"
fi

if [ -z "$OPENSSL_LIBCRYPTO_SO" ] || [ ! -f "$OPENSSL_LIBCRYPTO_SO" ]; then
    echo "ERROR: Cannot find OpenSSL shared library (libcrypto.so)."
    echo "  Searched near: $(dirname "$OPENSSL_LIBCRYPTO")"
    echo "  The differential harness requires a .so for dlopen."
    exit 1
fi

# Verify paths exist
echo "  AWSLC_LIBCRYPTO = $AWSLC_LIBCRYPTO"
echo "  AWSLC_INCLUDE   = $AWSLC_INCLUDE"
echo "  OPENSSL_SO      = $OPENSSL_LIBCRYPTO_SO"

for var in AWSLC_LIBCRYPTO AWSLC_INCLUDE; do
    val="${!var}"
    if [ ! -e "$val" ]; then
        echo "ERROR: $var path does not exist: $val"
        exit 1
    fi
done

echo ""
echo "Building differential harness..."
cd "$SCRIPT_DIR"

# openssl_ref.c uses dlopen — no OpenSSL headers needed at compile time
${CC:-gcc} -Wall -Wextra -O2 -g -c -o openssl_ref.o openssl_ref.c

# awslc_ref.c compiled against aws-lc headers
${CC:-gcc} -Wall -Wextra -O2 -g -I"$AWSLC_INCLUDE" -c -o awslc_ref.o awslc_ref.c

# Main harness — no library headers needed
${CC:-gcc} -Wall -Wextra -O2 -g -c -o ed448_diff_harness.o ed448_diff_harness.c

# Link: aws-lc static, OpenSSL via dlopen (only need -ldl)
${CC:-gcc} -Wall -Wextra -O2 -g -o ed448_diff_test \
    ed448_diff_harness.o awslc_ref.o openssl_ref.o \
    "$AWSLC_LIBCRYPTO" \
    -lpthread -ldl -lm

echo "Build successful."
echo ""

# Verify we linked aws-lc (not OpenSSL) statically
echo "=== Library verification ==="
echo "aws-lc libcrypto (static): $AWSLC_LIBCRYPTO"
echo "OpenSSL libcrypto (dlopen): $OPENSSL_LIBCRYPTO_SO"

# Check that our binary doesn't directly link OpenSSL
if ldd ed448_diff_test 2>/dev/null | grep -q "libcrypto"; then
    echo "  WARNING: binary links libcrypto dynamically — may be a system lib"
else
    echo "  OK: no dynamic libcrypto link (aws-lc is static, OpenSSL via dlopen)"
fi
echo ""

echo "=== Running differential test ==="
SEED="${1:-0xED448CAFE0001}"
./ed448_diff_test "$SEED" "$OPENSSL_LIBCRYPTO_SO"
