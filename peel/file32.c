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
LOGICAL EXPORT LIBCALL PlAttachFile32(IN const void* const pFileBase, OUT RAW_PE32* rpe) {

    rpe->pDosHdr = (DOS_HEADER*)pFileBase;
#if ! ACCEPT_INVALID_SIGNATURES
    if (rpe->pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return LOGICAL_FALSE;
#endif
    rpe->pDosStub = (DOS_STUB*)((PTR)rpe->pDosHdr + sizeof(DOS_HEADER));
    rpe->pNtHdr = (NT_HEADERS32*)((PTR)rpe->pDosHdr + rpe->pDosHdr->e_lfanew);
#if ACCEPT_INVALID_SIGNATURES
    if (rpe->pNtHdr->Signature != IMAGE_NT_SIGNATURE
     || rpe->pNtHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return LOGICAL_FALSE;
#endif
    if (rpe->pNtHdr->FileHeader.NumberOfSections) {
        rpe->ppSecHdr = (SECTION_HEADER**)malloc(rpe->pNtHdr->FileHeader.NumberOfSections * sizeof(SECTION_HEADER*));
        if (rpe->ppSecHdr == NULL)
            return LOGICAL_MAYBE;
        rpe->ppSectionData = (void**)malloc(rpe->pNtHdr->FileHeader.NumberOfSections * sizeof(void*));
        if (rpe->ppSectionData == NULL)
            return LOGICAL_MAYBE;
        for (register size_t i = 0; i < rpe->pNtHdr->FileHeader.NumberOfSections; ++i) {
            rpe->ppSecHdr[i] = (SECTION_HEADER*)((PTR)&rpe->pNtHdr->OptionalHeader + rpe->pNtHdr->FileHeader.SizeOfOptionalHeader + sizeof(SECTION_HEADER) * i);
            rpe->ppSectionData[i] = (void*)((PTR)rpe->pDosHdr + rpe->ppSecHdr[i]->PointerToRawData);
        }
    } else {
        rpe->ppSecHdr = NULL;
        rpe->ppSectionData = NULL;
        dmsg(TEXT("\nPE file at 0x%p has 0 sections!"), rpe->pDosHdr);
    }
    memset(&rpe->LoadStatus, 0, sizeof(rpe->LoadStatus));
    rpe->LoadStatus.Attached = TRUE;
    dmsg(TEXT("\nAttached to PE file at 0x%p"), rpe->pDosHdr);
    return LOGICAL_TRUE;
}

/// <summary>
///	Zeros and deallocates memory from an attached RAW_PE32. Only call if rpe::LoadStatus::Attached == TRUE </summary>
///
/// <param name="rpe">
/// Pointer to RAW_PE32 struct that is filled </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE/memory error, LOGICAL_MAYBE on CRT error </returns>
LOGICAL EXPORT LIBCALL PlDetachFile32(INOUT RAW_PE32* rpe) {
    if (!rpe->LoadStatus.Attached)
        return LOGICAL_FALSE;
    if (rpe->ppSecHdr != NULL)
        free(rpe->ppSecHdr);
    if (rpe->ppSectionData != NULL)
        free(rpe->ppSectionData);
    dmsg(TEXT("\nDetached from PE file at 0x%p"), rpe->pDosHdr);
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
LOGICAL EXPORT LIBCALL PlFileToImage32(IN const RAW_PE32* rpe, OUT VIRTUAL_MODULE32* vm) {
    PTR32 MaxRva = 0;
    void* pImage = NULL;

    if (!LOGICAL_SUCCESS(PlMaxRva32(rpe, &MaxRva)))
        return LOGICAL_FALSE;
    pImage = VirtualAlloc(NULL, MaxRva, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (pImage == NULL)
        return LOGICAL_MAYBE;
    return PlFileToImage32Ex(rpe, (void*)pImage, vm);
}

/// <summary>
///	Converts file to image alignment into provided buffer </summary>
///
/// <param name="rpe">
/// Pointer to RAW_PE32 containing file </param>
/// <param name="pBuffer">
/// Pointer to a buffer of at least PlMaxRva32(rpe,) bytes with at least PAGE_READWRITE access
/// <param name="vm">
/// Pointer to VIRTUAL_MODULE32 struct to recieve </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT/memory error </returns>
LOGICAL EXPORT LIBCALL PlFileToImage32Ex(IN const RAW_PE32* rpe, IN const void* pBuffer, OUT VIRTUAL_MODULE32* vm) {
    PTR32 MaxRva = 0;

    // unnecessary per standard, but let's play nice with gaps
    if (!LOGICAL_SUCCESS(PlMaxRva32(rpe, &MaxRva)))
        return LOGICAL_FALSE;
    memset((void*)pBuffer, 0, MaxRva);

    vm->pBaseAddr = (void*)pBuffer;
    vm->PE.pDosHdr = (DOS_HEADER*)vm->pBaseAddr;
    memmove(vm->PE.pDosHdr, rpe->pDosHdr, sizeof(DOS_HEADER));
    vm->PE.pDosStub = (DOS_STUB*)((PTR)vm->pBaseAddr + sizeof(DOS_HEADER));
    memmove(vm->PE.pDosStub, rpe->pDosStub, rpe->pDosHdr->e_lfanew - sizeof(DOS_HEADER));
    vm->PE.pNtHdr = (NT_HEADERS32*)((PTR)vm->pBaseAddr + vm->PE.pDosHdr->e_lfanew);
    memmove(vm->PE.pNtHdr, rpe->pNtHdr, sizeof(NT_HEADERS32));
    if (vm->PE.pNtHdr->FileHeader.NumberOfSections) {
        vm->PE.ppSecHdr = (SECTION_HEADER**)malloc(vm->PE.pNtHdr->FileHeader.NumberOfSections * sizeof(SECTION_HEADER*));
        if (vm->PE.ppSecHdr == NULL)
            return LOGICAL_MAYBE;
        vm->PE.ppSectionData = (void**)malloc(vm->PE.pNtHdr->FileHeader.NumberOfSections * sizeof(void*));
        if (vm->PE.ppSectionData == NULL)
            return LOGICAL_MAYBE;
        for (register size_t i = 0; i < vm->PE.pNtHdr->FileHeader.NumberOfSections; ++i) {
            vm->PE.ppSecHdr[i] = (SECTION_HEADER*)((PTR)&vm->PE.pNtHdr->OptionalHeader + vm->PE.pNtHdr->FileHeader.SizeOfOptionalHeader + sizeof(SECTION_HEADER) * i);
            memmove(vm->PE.ppSecHdr[i], rpe->ppSecHdr[i], sizeof(SECTION_HEADER));
            vm->PE.ppSectionData[i] = (void*)((PTR)vm->pBaseAddr + vm->PE.ppSecHdr[i]->VirtualAddress);
            memmove(vm->PE.ppSectionData[i], rpe->ppSectionData[i], vm->PE.ppSecHdr[i]->Misc.VirtualSize);  // virtualsize isn't aligned (may break codecaves)
        }
    } else {
        vm->PE.ppSecHdr = NULL;
        vm->PE.ppSectionData = NULL;
    }
    memset(&vm->PE.LoadStatus, 0, sizeof(PE_FLAGS));
    vm->PE.LoadStatus = rpe->LoadStatus;
    vm->PE.LoadStatus.Attached = FALSE;
    return LOGICAL_TRUE;
}

/// <summary>
///	Copies a file and fills crpe </summary>
///
/// <param name="rpe">
/// Pointer to RAW_PE32 containing file </param>
/// <param name="vm">
/// Pointer to VIRTUAL_MODULE32 struct to recieve </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT/memory error </returns>
LOGICAL EXPORT LIBCALL PlCopyFile32(IN const RAW_PE32* rpe, OUT RAW_PE32* crpe) {
    PTR32 MaxPa = 0;
    void* pCopy = NULL;

    if (!LOGICAL_SUCCESS(PlMaxRva32(rpe, &MaxPa)))
        return LOGICAL_FALSE;
    pCopy = VirtualAlloc(NULL, MaxPa, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (pCopy == NULL)
        return LOGICAL_MAYBE;
    return PlCopyFile32Ex(rpe, (void*)pCopy, crpe);
}

/// <summary>
///	Copies a file into provided buffer and fills in crpe with new information </summary>
///
/// <param name="rpe">
/// Pointer to RAW_PE32 containing file </param>
/// <param name="pBuffer">
/// Pointer to a buffer of at least PlMaxPa32(rpe,) bytes with at least PAGE_READWRITE access
/// <param name="crpe">
/// Pointer to RAW_PE32 that will recieve copy info </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT/memory error </returns>
LOGICAL EXPORT LIBCALL PlCopyFile32Ex(IN const RAW_PE32* rpe, IN const void* pBuffer, OUT RAW_PE32* crpe) {
    PTR32 MaxPa = 0;

    // unnecessary per standard, but let's play nice with gaps
    if (!LOGICAL_SUCCESS(PlMaxPa32(rpe, &MaxPa)))
        return LOGICAL_FALSE;
    memset((void*)pBuffer, 0, MaxPa);

    crpe->pDosHdr = (DOS_HEADER*)pBuffer;
    memmove(crpe->pDosHdr, rpe->pDosHdr, sizeof(DOS_HEADER));
    crpe->pDosStub = (DOS_STUB*)((PTR)crpe->pDosHdr + sizeof(DOS_HEADER));
    memmove(crpe->pDosStub, rpe->pDosStub, (PTR)crpe->pDosHdr->e_lfanew - sizeof(DOS_HEADER));
    crpe->pNtHdr = (NT_HEADERS32*)((PTR)crpe->pDosHdr + crpe->pDosHdr->e_lfanew);
    memmove(crpe->pNtHdr, rpe->pNtHdr, sizeof(NT_HEADERS32));
    if (crpe->pNtHdr->FileHeader.NumberOfSections) {
        crpe->ppSecHdr = (SECTION_HEADER**)malloc(crpe->pNtHdr->FileHeader.NumberOfSections * sizeof(SECTION_HEADER*));
        if (crpe->ppSecHdr == NULL)
            return LOGICAL_MAYBE;
        crpe->ppSectionData = (void**)malloc(crpe->pNtHdr->FileHeader.NumberOfSections * sizeof(void*));
        if (crpe->ppSectionData == NULL)
            return LOGICAL_MAYBE;
        for (register size_t i = 0; i < crpe->pNtHdr->FileHeader.NumberOfSections; ++i) {
            crpe->ppSecHdr[i] = (SECTION_HEADER*)((PTR)&crpe->pNtHdr->OptionalHeader + crpe->pNtHdr->FileHeader.SizeOfOptionalHeader + sizeof(SECTION_HEADER) * i);
            memmove(crpe->ppSecHdr[i], rpe->ppSecHdr[i], sizeof(SECTION_HEADER));
            crpe->ppSectionData[i] = (void*)((PTR)crpe->pDosHdr + crpe->ppSecHdr[i]->PointerToRawData);
            memmove(crpe->ppSectionData[i], rpe->ppSectionData[i], crpe->ppSecHdr[i]->SizeOfRawData);
        }
    } else {
        crpe->ppSecHdr = NULL;
        crpe->ppSectionData = NULL;
    }
    memset(&crpe->LoadStatus, 0, sizeof(PE_FLAGS));
    crpe->LoadStatus = rpe->LoadStatus;
    crpe->LoadStatus.Attached = FALSE;
    return LOGICAL_TRUE;
}

/// <summary>
///	Frees a file that was allocated </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE32 struct that is not attached </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT/memory error, *vm is zeroed </returns>
LOGICAL EXPORT LIBCALL PlFreeFile32(INOUT RAW_PE32* rpe) {
    if (rpe->LoadStatus.Attached == TRUE)
        return LOGICAL_FALSE;

    if (rpe->ppSecHdr != NULL)
        free(rpe->ppSecHdr);
    if (rpe->ppSectionData != NULL)
        free(rpe->ppSectionData);
    VirtualFree(rpe->pDosHdr, 0, MEM_RELEASE);
    memset(rpe, 0, sizeof(RAW_PE32));
    return LOGICAL_TRUE;
}