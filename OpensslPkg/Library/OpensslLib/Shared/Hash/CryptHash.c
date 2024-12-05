#include "CryptHash.h"

VOID HashInitFunctions (
    HashFunctions  *HashFuncs
    )
{
    InitMd5Support(HashFuncs);
    InitSha1Support(HashFuncs);
    InitSha256Support(HashFuncs);
    InitSha512Support(HashFuncs);
}