/** @file
  UEFI-specific replacement for OpenSSL's crypto/evp/enc_b64_avx2.c.

  The upstream file provides an AVX2-accelerated base64 encoder and pulls in
  <immintrin.h>. Under the UEFI build the OpenSSL sources are compiled with
  _WIN64/_MSC_VER undefined (see the OPENSSL_FLAGS_* BuildOptions), which makes
  the MSVC CRT headers that <immintrin.h> drags in mis-detect a 32-bit target
  and re-typedef size_t/ptrdiff_t/intptr_t, colliding with the UEFI CRT shim
  (error C2371: redefinition; different basic types). AVX2/YMM state is also
  not enabled in the UEFI execution environment.

  This replacement implements encode_base64_avx2() as a thin scalar wrapper
  that delegates to evp_encodeblock_int(). OpenSSL itself treats these as
  interchangeable: the non-AVX2 fallbacks in crypto/evp/encode.c call
  evp_encodeblock_int() with the very same arguments (the extra "newlines"
  parameter is derived from ctx inside evp_encodeblock_int), so the output is
  byte-for-byte identical.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <openssl/evp.h>
#include <stddef.h>

#if defined (__x86_64) || defined (__x86_64__) || defined (_M_AMD64) || defined (_M_X64)
#if !defined (_M_ARM64EC)

//
// Prototype from crypto/evp/enc_b64_scalar.h (the scalar base64 encoder).
//
size_t
evp_encodeblock_int (
  EVP_ENCODE_CTX       *ctx,
  unsigned char        *t,
  const unsigned char  *f,
  int                  dlen,
  int                  *wrap_cnt
  );

size_t
encode_base64_avx2 (
  EVP_ENCODE_CTX       *ctx,
  unsigned char        *out,
  const unsigned char  *src,
  int                  srclen,
  int                  newlines,
  int                  *wrap_cnt
  )
{
  //
  // "newlines" is only a hint used by the AVX2 code path; evp_encodeblock_int
  // derives the wrapping behavior from ctx, matching encode.c's scalar path.
  //
  (void)newlines;
  return evp_encodeblock_int (ctx, out, src, srclen, wrap_cnt);
}

#endif /* !defined (_M_ARM64EC) */
#endif
