#ifndef _CRYPT_BN_H_
#define _CRYPT_BN_H_

#include <Uefi.h>

/**
 * @typedef BigNumInitFunc
 * @brief Function pointer type for initializing a big number.
 * @return A pointer to the initialized big number.
 */
typedef VOID *(*BigNumInitFunc)(
  VOID
  );

/**
 * @typedef BigNumFromBinFunc
 * @brief Function pointer type for creating a big number from a binary buffer.
 * @param Buf The binary buffer.
 * @param Len The length of the binary buffer.
 * @return A pointer to the created big number.
 */
typedef VOID *(*BigNumFromBinFunc)(
  IN CONST UINT8  *Buf,
  IN UINTN        Len
  );

/**
 * @typedef BigNumToBinFunc
 * @brief Function pointer type for converting a big number to a binary buffer.
 * @param Bn The big number to convert.
 * @param Buf The output binary buffer.
 * @return The length of the binary buffer.
 */
typedef INTN (*BigNumToBinFunc)(
  IN CONST VOID  *Bn,
  OUT UINT8      *Buf
  );

/**
 * @typedef BigNumFreeFunc
 * @brief Function pointer type for freeing a big number.
 * @param Bn The big number to free.
 * @param Clear Whether to clear the memory before freeing.
 */
typedef VOID (*BigNumFreeFunc)(
  IN VOID     *Bn,
  IN BOOLEAN  Clear
  );

/**
 * @typedef BigNumAddFunc
 * @brief Function pointer type for adding two big numbers.
 * @param BnA The first big number.
 * @param BnB The second big number.
 * @param BnRes The result of the addition.
 * @return TRUE if the addition was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumAddFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumSubFunc
 * @brief Function pointer type for subtracting one big number from another.
 * @param BnA The big number to subtract from.
 * @param BnB The big number to subtract.
 * @param BnRes The result of the subtraction.
 * @return TRUE if the subtraction was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumSubFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumModFunc
 * @brief Function pointer type for computing the modulus of two big numbers.
 * @param BnA The dividend big number.
 * @param BnB The divisor big number.
 * @param BnRes The result of the modulus operation.
 * @return TRUE if the modulus operation was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumModFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumExpModFunc
 * @brief Function pointer type for computing the modular exponentiation of a big number.
 * @param BnA The base big number.
 * @param BnP The exponent big number.
 * @param BnM The modulus big number.
 * @param BnRes The result of the modular exponentiation.
 * @return TRUE if the modular exponentiation was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumExpModFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnP,
  IN CONST VOID  *BnM,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumInverseModFunc
 * @brief Function pointer type for computing the modular inverse of a big number.
 * @param BnA The big number to invert.
 * @param BnM The modulus big number.
 * @param BnRes The result of the modular inverse.
 * @return TRUE if the modular inverse was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumInverseModFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnM,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumDivFunc
 * @brief Function pointer type for dividing one big number by another.
 * @param BnA The dividend big number.
 * @param BnB The divisor big number.
 * @param BnRes The result of the division.
 * @return TRUE if the division was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumDivFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumMulModFunc
 * @brief Function pointer type for computing the modular multiplication of two big numbers.
 * @param BnA The first big number.
 * @param BnB The second big number.
 * @param BnM The modulus big number.
 * @param BnRes The result of the modular multiplication.
 * @return TRUE if the modular multiplication was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumMulModFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  IN CONST VOID  *BnM,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumCmpFunc
 * @brief Function pointer type for comparing two big numbers.
 * @param BnA The first big number.
 * @param BnB The second big number.
 * @return A negative value if BnA < BnB, zero if BnA == BnB, and a positive value if BnA > BnB.
 */
typedef INTN (*BigNumCmpFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB
  );

/**
 * @typedef BigNumBitsFunc
 * @brief Function pointer type for getting the number of bits in a big number.
 * @param Bn The big number.
 * @return The number of bits in the big number.
 */
typedef UINTN (*BigNumBitsFunc)(
  IN CONST VOID  *Bn
  );

/**
 * @typedef BigNumBytesFunc
 * @brief Function pointer type for getting the number of bytes in a big number.
 * @param Bn The big number.
 * @return The number of bytes in the big number.
 */
typedef UINTN (*BigNumBytesFunc)(
  IN CONST VOID  *Bn
  );

/**
 * @typedef BigNumIsWordFunc
 * @brief Function pointer type for checking if a big number is equal to a specific word.
 * @param Bn The big number.
 * @param Num The word to compare against.
 * @return TRUE if the big number is equal to the word, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumIsWordFunc)(
  IN CONST VOID  *Bn,
  IN UINTN       Num
  );

/**
 * @typedef BigNumIsOddFunc
 * @brief Function pointer type for checking if a big number is odd.
 * @param Bn The big number.
 * @return TRUE if the big number is odd, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumIsOddFunc)(
  IN CONST VOID  *Bn
  );

/**
 * @typedef BigNumCopyFunc
 * @brief Function pointer type for copying one big number to another.
 * @param BnDst The destination big number.
 * @param BnSrc The source big number.
 * @return A pointer to the destination big number.
 */
typedef VOID *(*BigNumCopyFunc)(
  OUT VOID       *BnDst,
  IN CONST VOID  *BnSrc
  );

/**
 * @typedef BigNumValueOneFunc
 * @brief Function pointer type for getting a big number representing the value one.
 * @return A pointer to the big number representing the value one.
 */
typedef CONST VOID *(*BigNumValueOneFunc)(
  VOID
  );

/**
 * @typedef BigNumRShiftFunc
 * @brief Function pointer type for right-shifting a big number by a specified number of bits.
 * @param Bn The big number to shift.
 * @param N The number of bits to shift.
 * @param BnRes The result of the right shift.
 * @return TRUE if the right shift was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumRShiftFunc)(
  IN CONST VOID  *Bn,
  IN UINTN       N,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumConstTimeFunc
 * @brief Function pointer type for performing a constant-time operation on a big number.
 * @param Bn The big number.
 */
typedef VOID (*BigNumConstTimeFunc)(
  IN VOID  *Bn
  );

/**
 * @typedef BigNumSqrModFunc
 * @brief Function pointer type for computing the modular square of a big number.
 * @param BnA The big number to square.
 * @param BnM The modulus big number.
 * @param BnRes The result of the modular square.
 * @return TRUE if the modular square was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumSqrModFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnM,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumNewContextFunc
 * @brief Function pointer type for creating a new big number context.
 * @return A pointer to the new big number context.
 */
typedef VOID *(*BigNumNewContextFunc)(
  VOID
  );

/**
 * @typedef BigNumContextFreeFunc
 * @brief Function pointer type for freeing a big number context.
 * @param BnCtx The big number context to free.
 */
typedef VOID (*BigNumContextFreeFunc)(
  IN VOID  *BnCtx
  );

/**
 * @typedef BigNumSetUintFunc
 * @brief Function pointer type for setting a big number to a specific unsigned integer value.
 * @param Bn The big number.
 * @param Val The unsigned integer value.
 * @return TRUE if the operation was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumSetUintFunc)(
  IN VOID   *Bn,
  IN UINTN  Val
  );

/**
 * @typedef BigNumAddModFunc
 * @brief Function pointer type for computing the modular addition of two big numbers.
 * @param BnA The first big number.
 * @param BnB The second big number.
 * @param BnM The modulus big number.
 * @param BnRes The result of the modular addition.
 * @return TRUE if the modular addition was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumAddModFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  IN CONST VOID  *BnM,
  OUT VOID       *BnRes
  );

#define BIGNUM_FUNCTIONS_SIGNATURE  SIGNATURE_32('B', 'N', 'F', 'S')
#define BIGNUM_FUNCTIONS_VERSION    1

typedef struct {
  UINT32                   Signature; // Signature of the structure to verify this is the intended structure
  UINT32                   Version;   // Version of the structure to handle backward compatibility
  BigNumInitFunc           Init;
  BigNumFromBinFunc        FromBin;
  BigNumToBinFunc          ToBin;
  BigNumFreeFunc           Free;
  BigNumAddFunc            Add;
  BigNumSubFunc            Sub;
  BigNumModFunc            Mod;
  BigNumExpModFunc         ExpMod;
  BigNumInverseModFunc     InverseMod;
  BigNumDivFunc            Div;
  BigNumMulModFunc         MulMod;
  BigNumCmpFunc            Cmp;
  BigNumBitsFunc           Bits;
  BigNumBytesFunc          Bytes;
  BigNumIsWordFunc         IsWord;
  BigNumIsOddFunc          IsOdd;
  BigNumCopyFunc           Copy;
  BigNumValueOneFunc       ValueOne;
  BigNumRShiftFunc         RShift;
  BigNumConstTimeFunc      ConstTime;
  BigNumSqrModFunc         SqrMod;
  BigNumNewContextFunc     NewContext;
  BigNumContextFreeFunc    ContextFree;
  BigNumSetUintFunc        SetUint;
  BigNumAddModFunc         AddMod;
} BigNumFunctions;


VOID
EFIAPI
BigNumInitFunctions (
  OUT BigNumFunctions  *Funcs
  );

#endif // _CRYPT_BN_H_
