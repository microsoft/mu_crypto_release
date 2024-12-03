#include <CrtLibSupport.h>


INT64
EFIAPI
InternalMathDivRemS64x64 (
  IN      INT64  Dividend,
  IN      INT64  Divisor,
  OUT     INT64  *Remainder  OPTIONAL
  )
{
  if (Remainder != NULL) {
    *Remainder = Dividend % Divisor;
  }

  return Dividend / Divisor;
}

INT64
EFIAPI
DivS64x64Remainder (
  IN      INT64  Dividend,
  IN      INT64  Divisor,
  OUT     INT64  *Remainder  OPTIONAL
  )
{
  ASSERT (Divisor != 0);
  return InternalMathDivRemS64x64 (Dividend, Divisor, Remainder);
}
