#ifndef CRYPT_RAND_H
#define CRYPT_RAND_H

#include <Uefi.h>

/**
  Sets up the seed value for the pseudorandom number generator.

  This function sets up the seed value for the pseudorandom number generator.
  If Seed is not NULL, then the seed passed in is used.
  If Seed is NULL, then default seed is used.

  @param[in]  Seed      Pointer to seed value.
                        If NULL, default seed is used.
  @param[in]  SeedSize  Size of seed value.
                        If Seed is NULL, this parameter is ignored.

  @retval TRUE   Pseudorandom number generator has enough entropy for random generation.
  @retval FALSE  Pseudorandom number generator does not have enough entropy for random generation.

**/
BOOLEAN
EFIAPI
RandomSeed (
  IN  CONST  UINT8  *Seed  OPTIONAL,
  IN  UINTN         SeedSize
  );

/**
  Generates a pseudorandom byte stream of the specified size.

  If Output is NULL, then return FALSE.

  @param[out]  Output  Pointer to buffer to receive random value.
  @param[in]   Size    Size of random bytes to generate.

  @retval TRUE   Pseudorandom byte stream generated successfully.
  @retval FALSE  Pseudorandom number generator fails to generate due to lack of entropy.

**/
BOOLEAN
EFIAPI
RandomBytes (
  OUT  UINT8  *Output,
  IN   UINTN  Size
  );

#endif // CRYPT_RAND_H
