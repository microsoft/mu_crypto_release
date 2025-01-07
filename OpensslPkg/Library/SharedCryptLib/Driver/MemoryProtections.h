#ifndef SHARED_LOADER_MEMORY_PROTECTIONS_
#define SHARED_LOADER_MEMORY_PROTECTIONS_

#include <Uefi.h>
#include <Uefi/UefiSpec.h>

#include "PeCoffLib.h"

/*
*/
EFI_STATUS
ProtectUefiDll(
    INTERNAL_IMAGE_CONTEXT  *Image
);


#endif // SHARED_LOADER_MEMORY_PROTECTIONS