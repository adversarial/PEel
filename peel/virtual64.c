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

#include "virtual64.h"

/// <summary>
///	Fills VIRTUAL_MODULE64 with loaded image's information </summary>
///
/// <param name="pModuleBase">
/// Base address of target image </param>
/// <param name="vm">
/// Pointer to VIRTUAL_MODULE64 struct to recieve information about target </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT error </returns>
LOGICAL EXPORT LIBCALL PlAttachImage64(IN const void* const pModuleBase, OUT VIRTUAL_MODULE64* vm) {
    
    // leave other members alone (name needs to be set externally)
    memset(&vm->PE, 0, sizeof(RAW_PE64));

    vm->pBaseAddr = (void*)pModuleBase;
    vm->PE.pDosHdr = (DOS_HEADER*)pModuleBase;
#if ! ACCEPT_INVALID_SIGNATURES
    if (vm->PE.pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return LOGICAL_FALSE;
#endif
    vm->PE.pDosStub = (DOS_STUB*)((PTR)vm->pBaseAddr + sizeof(DOS_HEADER));
    vm->PE.pNtHdr = (NT_HEADERS64*)((PTR)vm->pBaseAddr + vm->PE.pDosHdr->e_lfanew);
#if ! ACCEPT_INVALID_SIGNATURES
    if (vm->PE.pNtHdr->Signature != IMAGE_NT_SIGNATURE
     || vm->PE.pNtHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        dmsg(TEXT("\nNT Headers signature or magic invalid!"));
        return LOGICAL_FALSE;
    }
#endif
    if (vm->PE.pNtHdr->FileHeader.NumberOfSections) {
        vm->PE.ppSecHdr = (SECTION_HEADER**)malloc(vm->PE.pNtHdr->FileHeader.NumberOfSections * sizeof(SECTION_HEADER*));
        if (vm->PE.ppSecHdr == NULL)
            return LOGICAL_MAYBE;
        vm->PE.ppSectionData = (void**)malloc(vm->PE.pNtHdr->FileHeader.NumberOfSections * sizeof(void*));
        if (vm->PE.ppSectionData == NULL)
            return LOGICAL_MAYBE;
        for (register size_t i = 0; i < vm->PE.pNtHdr->FileHeader.NumberOfSections; ++i) {
            vm->PE.ppSecHdr[i] = (SECTION_HEADER*)((PTR)&vm->PE.pNtHdr->OptionalHeader + vm->PE.pNtHdr->FileHeader.SizeOfOptionalHeader + (sizeof(SECTION_HEADER) * i));
            vm->PE.ppSectionData[i] = (void*)((PTR)vm->pBaseAddr + vm->PE.ppSecHdr[i]->VirtualAddress);
        }
    } else {
        vm->PE.ppSecHdr = NULL;
        vm->PE.ppSectionData = NULL;
        dmsg(TEXT("\nPE image at 0x%p has 0 sections!"), vm->pBaseAddr);
    }
    memset(&vm->PE.LoadStatus, 0, sizeof(vm->PE.LoadStatus));
    vm->PE.LoadStatus.Attached = TRUE;
    dmsg(TEXT("\nAttached to PE image at 0x%p"), vm->pBaseAddr);
    return LOGICAL_TRUE;
}