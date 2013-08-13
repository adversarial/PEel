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

#include "file32.h"

/// <summary>
///	Fills VIRTUAL_PE32 with char* file's information </summary>
///
/// <param name="pModuleBase">
/// Address of char* file target </param>
/// <param name="vpe">
/// Pointer to VIRTUAL_PE32 struct to recieve information about target </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT error </returns>
LOGICAL EXPORT LIBCALL MrAttachFile32(IN const void* const pFileBase, OUT RAW_PE32* rpe) {
    unsigned int i;

    rpe->pIDH = (DOS_HEADER*)pFileBase;
#if ! ACCEPT_INVALID_SIGNATURES
    if (rpe->pIDH->e_magic != IMAGE_DOS_SIGNATURE)
        return LOGICAL_FALSE;
#endif
    rpe->pIDS = (DOS_STUB*)((PTR)rpe->pIDH + sizeof(DOS_HEADER));
    rpe->pINH = (NT_HEADERS32*)((PTR)rpe->pIDH + rpe->pIDH->e_lfanew);
#if ACCEPT_INVALID_SIGNATURES
    if (rpe->pINH->Signature != IMAGE_NT_SIGNATURE
     || rpe->pINH->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return LOGICAL_FALSE;
#endif
    if (rpe->pINH->FileHeader.NumberOfSections) {
        rpe->ppISH = (SECTION_HEADER**)malloc(rpe->pINH->FileHeader.NumberOfSections * sizeof(SECTION_HEADER*));
        if (rpe->ppISH == NULL)
            return LOGICAL_MAYBE;
        rpe->ppSectionData = (void**)malloc(rpe->pINH->FileHeader.NumberOfSections * sizeof(void*));
        if (rpe->ppSectionData == NULL)
            return LOGICAL_MAYBE;
        for (i = 0; i < rpe->pINH->FileHeader.NumberOfSections; ++i) {
            rpe->ppISH[i] = (SECTION_HEADER*)((PTR)&rpe->pINH->OptionalHeader + rpe->pINH->FileHeader.SizeOfOptionalHeader + sizeof(SECTION_HEADER) * i);
            rpe->ppSectionData[i] = (void*)((PTR)rpe->pIDH + rpe->ppISH[i]->PointerToRawData);
        }
    } else {
        rpe->ppISH = NULL;
        rpe->ppSectionData = NULL;
        dmsg(TEXT("\nPE file at 0x%p has 0 sections!"), rpe->pIDH);
    }
    memset(&rpe->dwFlags, 0, sizeof(rpe->dwFlags));
    rpe->dwFlags.Attached = TRUE;
    dmsg(TEXT("\nAttached to PE file at 0x%p"), rpe->pIDH);
    return LOGICAL_TRUE;
}

/// <summary>
///	Zeros and deallocates memory from an attached RAW_PE32. Only call if rpe::dwFlags::Attached == TRUE </summary>
///
/// <param name="rpe">
/// Pointer to RAW_PE32 struct that is filled </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE/memory error, LOGICAL_MAYBE on CRT error </returns>
LOGICAL EXPORT LIBCALL MrDetachFile32(INOUT RAW_PE32* rpe) {
    if (!rpe->dwFlags.Attached)
        return LOGICAL_FALSE;
    if (rpe->ppISH != NULL)
        free(rpe->ppISH);
    if (rpe->ppSectionData != NULL)
        free(rpe->ppSectionData);
    dmsg(TEXT("\nDetached from PE file at 0x%p"), rpe->pIDH);
    memset(rpe, 0, sizeof(RAW_PE32));
    return LOGICAL_TRUE;
}

/// <summary>
///	Converts file to image alignment </summary>
///
/// <param name="rpe">
/// Pointer to RAW_PE32 containing file </param>
/// <param name="vm">
/// Pointer to VIRTUAL_MODULE32 struct to recieve </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT/memory error </returns>
LOGICAL EXPORT LIBCALL MrFileToImage32(IN const RAW_PE32* rpe, OUT VIRTUAL_MODULE32* vm) {
    PTR32 MaxRva;
    void* pImage = NULL;

    if (!LOGICAL_SUCCESS(MrMaxRva32(rpe, &MaxRva)))
        return LOGICAL_FALSE;
    pImage = VirtualAlloc(NULL, MaxRva, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (pImage == NULL)
        return LOGICAL_MAYBE;
    return MrFileToImage32Ex(rpe, (PTR)pImage, vm);
}

/// <summary>
///	Converts file to image alignment into provided buffer </summary>
///
/// <param name="rpe">
/// Pointer to RAW_PE32 containing file </param>
/// <param name="pImageBuffer">
/// Pointer to a buffer of at least MrMaxRva32(rpe,) bytes with at least PAGE_READWRITE access
/// <param name="vm">
/// Pointer to VIRTUAL_MODULE32 struct to recieve </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT/memory error </returns>
LOGICAL EXPORT LIBCALL MrFileToImage32Ex(IN const RAW_PE32* rpe, IN const PTR pImageBuffer, OUT VIRTUAL_MODULE32* vm) {
    PTR32 MaxRva;
    unsigned int i;

    // unnecessary per standard, but let's play nice with gaps
    if (!LOGICAL_SUCCESS(MrMaxRva32(rpe, &MaxRva)))
        return LOGICAL_FALSE;
    memset((void*)pImageBuffer, 0, MaxRva);

    vm->pBaseAddr = (void*)pImageBuffer;
    vm->PE.pIDH = (DOS_HEADER*)vm->pBaseAddr;
    memcpy(vm->PE.pIDH, rpe->pIDH, sizeof(DOS_HEADER));
    vm->PE.pIDS = (DOS_STUB*)((PTR)vm->pBaseAddr + sizeof(DOS_HEADER));
    memcpy(vm->PE.pIDS, rpe->pIDS, rpe->pIDH->e_lfanew - sizeof(DOS_HEADER));
    vm->PE.pINH = (NT_HEADERS32*)((PTR)vm->pBaseAddr + vm->PE.pIDH->e_lfanew);
    memcpy(vm->PE.pINH, rpe->pINH, sizeof(NT_HEADERS32));
    if (vm->PE.pINH->FileHeader.NumberOfSections) {
        vm->PE.ppISH = (SECTION_HEADER**)malloc(vm->PE.pINH->FileHeader.NumberOfSections * sizeof(SECTION_HEADER*));
        if (vm->PE.ppISH == NULL)
            return LOGICAL_MAYBE;
        vm->PE.ppSectionData = (void**)malloc(vm->PE.pINH->FileHeader.NumberOfSections * sizeof(void*));
        if (vm->PE.ppSectionData == NULL)
            return LOGICAL_MAYBE;
        for (i = 0; i < vm->PE.pINH->FileHeader.NumberOfSections; ++i) {
            vm->PE.ppISH[i] = (SECTION_HEADER*)((PTR)&vm->PE.pINH->OptionalHeader + vm->PE.pINH->FileHeader.SizeOfOptionalHeader + sizeof(SECTION_HEADER) * i);
            memcpy(vm->PE.ppISH[i], rpe->ppISH[i], sizeof(SECTION_HEADER));
            vm->PE.ppSectionData[i] = (void*)((PTR)vm->pBaseAddr + vm->PE.ppISH[i]->PointerToRawData);
            memcpy(vm->PE.ppSectionData[i], rpe->ppSectionData[i], vm->PE.ppISH[i]->SizeOfRawData);
        }
    } else {
        vm->PE.ppISH = NULL;
        vm->PE.ppSectionData = NULL;
    }
    memset(&vm->PE.dwFlags, 0, sizeof(PE_FLAGS));
    vm->PE.dwFlags = rpe->dwFlags;
    vm->PE.dwFlags.Attached = FALSE;
    return LOGICAL_TRUE;
}

/// <summary>
///	Frees a file that was allocated </summary>
///
/// <param name="vm">
/// Loaded RAW_PE32 struct that is not attached </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT/memory error, *vm is zeroed </returns>
LOGICAL EXPORT LIBCALL MrFreeFile32(INOUT RAW_PE32* rpe) {
    if (rpe->dwFlags.Attached == TRUE)
        return LOGICAL_FALSE;

    if (rpe->ppISH != NULL)
        free(rpe->ppISH);
    if (rpe->ppSectionData != NULL)
        free(rpe->ppSectionData);
    VirtualFree(rpe->pIDH, 0, MEM_RELEASE);
    memset(rpe, 0, sizeof(RAW_PE32));
    return LOGICAL_TRUE;
}