/** @file
  Compile the production CRT wrappers without interposing on the host C library.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#define errno          CrtTestErrno
#define stderr         CrtTestStderr
#define stdin          CrtTestStdin
#define stdout         CrtTestStdout
#define strchr         CrtTestStrchr
#define strrchr        CrtTestStrrchr
#define strncasecmp    CrtTestStrncasecmp
#define sscanf         CrtTestSscanf
#define strerror       CrtTestStrerror
#define strspn         CrtTestStrspn
#define strcspn        CrtTestStrcspn
#define strcpy         CrtTestStrcpy
#define strncpy        CrtTestStrncpy
#define strcat         CrtTestStrcat
#define strcmp         CrtTestStrcmp
#define isdigit        CrtTestIsdigit
#define isxdigit       CrtTestIsxdigit
#define isspace        CrtTestIsspace
#define isalnum        CrtTestIsalnum
#define isupper        CrtTestIsupper
#define strtol         CrtTestStrtol
#define strtoul        CrtTestStrtoul
#define strpbrk        CrtTestStrpbrk
#define tolower        CrtTestTolower
#define qsort          CrtTestQsort
#define getenv         CrtTestGetenv
#define secure_getenv  CrtTestSecureGetenv
#define fwrite         CrtTestFwrite
#define abort          CrtTestAbort
#define fclose         CrtTestFclose
#define fopen          CrtTestFopen
#define fread          CrtTestFread
#define getuid         CrtTestGetuid
#define geteuid        CrtTestGeteuid
#define getgid         CrtTestGetgid
#define getegid        CrtTestGetegid
#define printf         CrtTestPrintf
#define vsnprintf      CrtTestVsnprintf
#define snprintf       CrtTestSnprintf
#define sprintf        CrtTestSprintf

#include "../../Library/BaseCryptLib/SysCall/CrtWrapper.c"
