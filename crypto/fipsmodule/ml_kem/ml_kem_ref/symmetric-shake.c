#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "symmetric.h"

#ifndef EXPERIMENTAL_AWS_LC_KECCAK_DESIGN_I
/*************************************************
* Name:        kyber_shake128_absorb
*
* Description: Absorb step of the SHAKE128 specialized for the Kyber context.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
*              - const uint8_t *seed: pointer to KYBER_SYMBYTES input to be absorbed into state
*              - uint8_t i: additional byte of input
*              - uint8_t j: additional byte of input
**************************************************/
void kyber_shake128_absorb(keccak_state *state,
                           const uint8_t seed[KYBER_SYMBYTES],
                           uint8_t x,
                           uint8_t y)
{
  uint8_t extseed[KYBER_SYMBYTES+2];

  memcpy(extseed, seed, KYBER_SYMBYTES);
  extseed[KYBER_SYMBYTES+0] = x;
  extseed[KYBER_SYMBYTES+1] = y;

  #ifndef EXPERIMENTAL_AWS_LC_KECCAK // Original Implementation

  shake128_absorb_once(state, extseed, sizeof(extseed));

  #else // AWS-LC SHA3 Implementations

  #ifdef EXPERIMENTAL_AWS_LC_KECCAK_DESIGN_IV
  int p = 0x1F; 

  for (int i = 0; i < 25; i++)
  {
    state->s[i] = 0;
  }
  
  int i = 0; 
  int rem = SHA3_Absorb((uint64_t (*)[5])state->s, extseed, sizeof(extseed), SHAKE128_RATE);
  
  for(i=0;i<rem;i++){
    state->s[i/8] ^= (uint64_t)extseed[i + sizeof(extseed) - rem] << 8*(i%8);
  }

  state->s[i/8] ^= (uint64_t)p << 8*(i%8);
  state->s[(SHAKE128_RATE-1)/8] ^= 1ULL << 63;

  #endif 
  #endif // EXPERIMENTAL_AWS_LC_KECCAK
  
}

#endif

#ifdef EXPERIMENTAL_AWS_LC_KECCAK_DESIGN_I
/*************************************************
* Name:        kyber_shake128_absorb
*
* Description: Absorb step of the SHAKE128 specialized for the Kyber context.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
*              - const uint8_t *seed: pointer to KYBER_SYMBYTES input to be absorbed into state
*              - uint8_t i: additional byte of input
*              - uint8_t j: additional byte of input
**************************************************/
void kyber_shake128_absorb(KECCAK1600_CTX *ctx,
                           const uint8_t seed[KYBER_SYMBYTES],
                           uint8_t x,
                           uint8_t y)
{
 uint8_t extseed[KYBER_SYMBYTES+2];

  memcpy(extseed, seed, KYBER_SYMBYTES);
  extseed[KYBER_SYMBYTES+0] = x;
  extseed[KYBER_SYMBYTES+1] = y;

  SHAKE_Init(ctx, SHAKE128_RATE);
  SHA3_Update(ctx, extseed, KYBER_SYMBYTES + 2);
}
#endif

#if defined(EXPERIMENTAL_AWS_LC_KECCAK) && !defined(EXPERIMENTAL_AWS_LC_KECCAK_DESIGN_I)
// TODO:: Some large description here
void kyber_shake128_squeeze(uint8_t *out, int nblocks, keccak_state *state)
{
  
  // Originally defined in fips202.c
  //shake128_squeezeblocks(out, nblocks, state);
  //#else
 
  #ifdef EXPERIMENTAL_AWS_LC_KECCAK_DESIGN_IV
  KeccakF1600((uint64_t (*)[5])state->s);
  SHA3_Squeeze((uint64_t (*)[5])state->s, out, (nblocks) * SHAKE128_RATE, SHAKE128_RATE, 1);
  #endif
}
#endif


#ifdef EXPERIMENTAL_AWS_LC_KECCAK_DESIGN_I
// TODO:: Some large description here
void kyber_shake128_squeeze(uint8_t *out, int nblocks, KECCAK1600_CTX *ctx)
{

  SHAKE_Final(out, ctx, nblocks*SHAKE128_RATE);
}
#endif
/*************************************************
* Name:        kyber_shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: number of requested output bytes
*              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
*              - uint8_t nonce: single-byte nonce (public PRF input)
**************************************************/
void kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce)
{
  uint8_t extkey[KYBER_SYMBYTES+1];

  memcpy(extkey, key, KYBER_SYMBYTES);
  extkey[KYBER_SYMBYTES] = nonce;

  #ifndef EXPERIMENTAL_AWS_LC_KECCAK
  shake256(out, outlen, extkey, sizeof(extkey)); 
  #else
  SHAKE256(extkey, sizeof(extkey), out, outlen);
  #endif

}

// Is that description accurate? No
/*************************************************
* Name:        kyber_shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: number of requested output bytes
*              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
*              - uint8_t nonce: single-byte nonce (public PRF input)
**************************************************/
void kyber_shake256_rkprf(ml_kem_params *params, uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t *input)
{

  #ifndef EXPERIMENTAL_AWS_LC_KECCAK
  keccak_state s;
  shake256_init(&s);
  shake256_absorb(&s, key, KYBER_SYMBYTES);
  shake256_absorb(&s, input, params->ciphertext_bytes);
  shake256_finalize(&s);
  shake256_squeeze(out, KYBER_SSBYTES, &s);
  #else

  KECCAK1600_CTX ctx;
  int ok = 0;
  ok = (SHAKE_Init(&ctx, SHAKE256_BLOCKSIZE));
  if (!ok) return;
  ok = SHA3_Update(&ctx, key, KYBER_SYMBYTES);
  if (!ok) return;
  SHA3_Update(&ctx, input, params->ciphertext_bytes);
  if (!ok) return;
  SHAKE_Final(out, &ctx, KYBER_SSBYTES);

  // Check if rejection key is computed correctly
  // Compare original result with AWS-LC shake function result
  // NOTE: The rejeciton key is not checked for correctness in a 
  // different way (no test vectors, however, it is a deterministic value)
  // if (memcmp(&(s.s), &(ctx.A), SHA3_WORDS) != 0){
  //     // There should be more elegant way ?? DONNO 
  //     printf("ERROR \n\n");
  //     return;
  // }
  #endif
}
