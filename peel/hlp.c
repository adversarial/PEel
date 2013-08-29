/*
* (C) Copyright 2013 x8esix.
*
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the GNU Lesser General Public License
* (LGPL) version 3.0 which accompanies this distribution, and is available at
* http://www.gnu.org/licenses/lgpl-3.0.txt
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
*/

#include "hlp.h"
#include <intrin.h>

void* EXPORT LIBCALL HlpGetCurrentPeb() {
#   ifdef _WIN32
        return (void*)__readfsdword(0x30);
#   elif _WIN64
        return (void*)__readgsqword(0x60);
#   else
        return NULL;
#   endif
}

LOGICAL EXPORT LIBCALL HlpReplaceImage32Ex(INOUT VIRTUAL_MODULE32* vmTarget, IN VIRTUAL_MODULE32* vmReplacement, OUT VIRTUAL_MODULE32* vmClone) {
    PTR32         dwMaxRvaTarget = 0,
                  dwMaxRvaReplacement = 0;
    PEB32        *pPeb;
    LDR_MODULE32 *plmModule,
                 *plmModuleHeader;
    wchar_t       wzName[9] = {0},
                  wzNameReplacement[9] = {0};

    if (!LOGICAL_SUCCESS(MrMaxRva32(&vmTarget->PE, &dwMaxRvaTarget))
     || !LOGICAL_SUCCESS(MrMaxRva32(&vmReplacement->PE, &dwMaxRvaReplacement)))
        return LOGICAL_FALSE;

    pPeb = (PEB32*)HlpGetCurrentPeb();
    if (pPeb == NULL) // not really possible unless not on intel
        return LOGICAL_FALSE;

    mbstowcs(wzName, vmTarget->cName, 8);
    mbstowcs(wzNameReplacement, vmReplacement->cName, 8);

  // WARNING undocumented WARNING
    plmModule = (LDR_MODULE32*)pPeb->Ldr;
    plmModuleHeader = plmModule;
    do {
      // search for target module (either 8 or smaller name)
        if (!wcsnicmp(wzName, plmModule->BaseDllName.Buffer, plmModule->BaseDllName.MaximumLength < 8 ? plmModule->BaseDllName.MaximumLength : 8)) {
          // start replacing with our module's information
            plmModule->BaseDllName.Length = plmModule->BaseDllName.MaximumLength < 8 ? (plmModule->BaseDllName.MaximumLength - 1) : wcslen(wzNameReplacement);
            memcpy(plmModule->BaseDllName.Buffer, wzNameReplacement, plmModule->BaseDllName.Length);
            plmModule->EntryPoint = (PVOID)((PTR)vmTarget->pBaseAddr + vmReplacement->PE.pNtHdr->OptionalHeader.AddressOfEntryPoint);
          // there's not really a way to provide a full name in 8 chars
            memset(&plmModule->FullDllName, 0, sizeof(plmModule->FullDllName));
          // fixups
            plmModule->SizeOfImage = dwMaxRvaReplacement;
          // if there's a TLS directory enable TLS
            plmModule->TlsIndex = vmReplacement->PE.pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0 ? -1 : 0;
          // we've found what we're looking for
            plmModule = plmModuleHeader;
            break;
        }
       
        plmModule = (LDR_MODULE32*)plmModule->InMemoryOrderModuleList.Flink;
    } while (plmModule != plmModuleHeader); // circular list

  // now update vmReplacement and copy the image
    MrCopyImage32Ex(vmReplacement, vmTarget->pBaseAddr, vmClone);
    if (!LOGICAL_SUCCESS(MrRelocate32(&vmClone->PE, (PTR32)vmReplacement->pBaseAddr, (PTR32)vmTarget->pBaseAddr)))
        return LOGICAL_FALSE;

    MrDetachImage32(vmTarget);
    return LOGICAL_TRUE;
}