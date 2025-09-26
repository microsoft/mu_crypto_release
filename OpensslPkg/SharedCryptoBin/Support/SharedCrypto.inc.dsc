
## @file
#  SharedCrypto.inc.dsc includes the SharedCrypto binary component
#
#  Copyright (c) Microsoft Corporation
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

# TODO rename SHARED_SHARED_CRYPTO_PATH to SHARED_CRYPTO_PATH

[Components.X64]
  # Common - Precompiled - Shared Component across phases 
  $(SHARED_SHARED_CRYPTO_PATH)/bin/shared/SharedCryptoMmBin.inf

  # Drivers that will be built from source to provide platform services
  $(SHARED_SHARED_CRYPTO_PATH)/src/driver/SharedCryptoLoaderDxe.inf

  $(SHARED_SHARED_CRYPTO_PATH)/src/driver/SharedCryptoLoaderMm.inf {
    <LibraryClasses>
      #PrePiLib|EmbeddedPkg/Library/PrePiLib/PrePiLib.inf
      FvLib|StandaloneMmPkg/Library/FvLib/FvLib.inf
      ExtractGuidedSectionLib|MdePkg/Library/BaseExtractGuidedSectionLib/BaseExtractGuidedSectionLib.inf
  }
