/*
 * Copyright (c) 2013 x8esix
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "virtual.h"
#include "raw.h"

/// <summary>
///	Fills VIRTUAL_MODULE with loaded image's information </summary>
///
/// <param name="pModuleBase">
/// Base address of target image </param>
/// <param name="vm">
/// Pointer to VIRTUAL_MODULE struct to recieve information about target </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT error </returns>
LOGICAL EXPORT LIBCALL PlAttachImage(IN const void* const pModuleBase, OUT VIRTUAL_MODULE* vm) {
    
    // leave other members alone (name needs to be set externally)
    memset(&vm->PE, 0, sizeof(vm->PE));

    vm->pBaseAddr = (void*)pModuleBase;
    vm->PE.pDosHdr = (DOS_HEADER*)pModuleBase;
#if ! ACCEPT_INVALID_SIGNATURES
    if (vm->PE.pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return LOGICAL_FALSE;
#endif
    vm->PE.pDosStub = (DOS_STUB*)((PTR)vm->pBaseAddr + sizeof(DOS_HEADER));
    vm->PE.pNtHdr = (NT_HEADERS*)((PTR)vm->pBaseAddr + vm->PE.pDosHdr->e_lfanew);
#if ! ACCEPT_INVALID_SIGNATURES
    if (vm->PE.pNtHdr->Signature != IMAGE_NT_SIGNATURE
     || vm->PE.pNtHdr->OptionalHeader.Magic != OPT_HDR_MAGIC) {
        dmsg(TEXT("\nNT Headers signature or magic invalid!"));
        return LOGICAL_FALSE;
    }
#endif
    if (vm->PE.pNtHdr->FileHeader.NumberOfSections) {
        WORD wNumSections = vm->PE.pNtHdr->FileHeader.NumberOfSections > MAX_SECTIONS ? MAX_SECTIONS : vm->PE.pNtHdr->FileHeader.NumberOfSections;
        if (vm->PE.pNtHdr->FileHeader.NumberOfSections > MAX_SECTIONS) 
            dmsg(TEXT("\nToo many sections to load, only loading %hu of %hu sections!"), MAX_SECTIONS, vm->PE.pNtHdr->FileHeader.NumberOfSections);

        vm->PE.ppSecHdr = malloc(wNumSections * sizeof(*vm->PE.ppSecHdr));
        if (vm->PE.ppSecHdr == NULL)
            return LOGICAL_MAYBE;
        vm->PE.ppSectionData = malloc(wNumSections * sizeof(*vm->PE.ppSectionData));
        if (vm->PE.ppSectionData == NULL)
            return LOGICAL_MAYBE;
        for (register size_t i = 0; i < wNumSections; ++i) {
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

/// <summary>
///	Releases memory allocated by XxAttachImage </summary>
///
/// <param name="vm">
/// Pointer to loaded VIRTUAL_MODULE struct </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT error </returns>
LOGICAL EXPORT LIBCALL PlDetachImage(INOUT VIRTUAL_MODULE* vm) {
    VIRTUAL_MODULE *vmNext = NULL,
                   *vmPrev = NULL;

    if (!LOGICAL_SUCCESS(PlDetachFile(&vm->PE)))
        return LOGICAL_FALSE;
    dmsg(TEXT("\nUnlinking PE Image at %p"), vm->pBaseAddr);
    vmPrev = (VIRTUAL_MODULE*)vm->Blink;
    vmNext = (VIRTUAL_MODULE*)vm->Flink;
    if (vmPrev != NULL)
        vmPrev->Flink = vmNext;
    if (vmNext != NULL)
        vmNext->Blink = vmPrev;
    dmsg(TEXT("\nDetached from PE image at 0x%p"), vm->pBaseAddr);
    memset(vm, 0, sizeof(*vm));
    return LOGICAL_TRUE;
}

/// <summary>
///	Converts image to file alignment </summary>
///
/// <param name="vpe">
/// Pointer to VIRTUAL_MODULE containing loaded image </param>
/// <param name="rpe">
/// Pointer to RAW_PE struct </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT/memory error </returns>
LOGICAL EXPORT LIBCALL PlImageToFile(IN const VIRTUAL_MODULE* vm, OUT RAW_PE* rpe) {
    PTR MaxPa = 0;
    void* pImage = NULL;

    if (!LOGICAL_SUCCESS(PlMaxPa(&vm->PE, &MaxPa)))
        return LOGICAL_FALSE;
    pImage = VirtualAlloc(NULL, MaxPa, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (pImage == NULL)
        return LOGICAL_MAYBE;
    return PlImageToFileEx(vm, pImage, rpe);
}

/// <summary>
///	Converts image to file alignment </summary>
///
/// <param name="vpe">
/// Pointer to VIRTUAL_MODULE containing loaded image </param>
/// <param name="pImageBuffer">
/// Buffer of at least PlMaxPa(&vm->Pe,) size with at least PAGE_READWRITE attributes
/// <param name="rpe">
/// Pointer to RAW_PE struct </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT/memory error </returns>
LOGICAL EXPORT LIBCALL PlImageToFileEx(IN const VIRTUAL_MODULE* vm, IN const void* pBuffer, OUT RAW_PE* rpe) {
    PTR MaxPa = 0;
    
    // unnecessary per standard, but let's play nice with gaps
    if (!LOGICAL_SUCCESS(PlMaxPa(&vm->PE, &MaxPa)))
        return LOGICAL_FALSE;
    memset((void*)pBuffer, 0, MaxPa);
    
    rpe->pDosHdr = (DOS_HEADER*)pBuffer;
    memmove(rpe->pDosHdr, vm->PE.pDosHdr, sizeof(DOS_HEADER));
    rpe->pDosStub = (DOS_STUB*)((PTR)rpe->pDosHdr + sizeof(DOS_HEADER));
    memmove(rpe->pDosStub, vm->PE.pDosStub, rpe->pDosHdr->e_lfanew - sizeof(DOS_HEADER));
    rpe->pNtHdr = (NT_HEADERS*)((PTR)rpe->pDosHdr + rpe->pDosHdr->e_lfanew);
    memmove(rpe->pNtHdr, vm->PE.pNtHdr, sizeof(NT_HEADERS));
    if (rpe->pNtHdr->FileHeader.NumberOfSections) {
        WORD wNumSections = vm->PE.pNtHdr->FileHeader.NumberOfSections > MAX_SECTIONS ? MAX_SECTIONS : vm->PE.pNtHdr->FileHeader.NumberOfSections;
        if (vm->PE.pNtHdr->FileHeader.NumberOfSections > MAX_SECTIONS) 
            dmsg(TEXT("\nToo many sections to load, only loading %hu of %hu sections!"), MAX_SECTIONS, vm->PE.pNtHdr->FileHeader.NumberOfSections);

        rpe->ppSecHdr = malloc(wNumSections * sizeof(*rpe->ppSecHdr));
        if (rpe->ppSecHdr == NULL)
            return LOGICAL_MAYBE;
        rpe->ppSectionData = malloc(wNumSections * sizeof(*rpe->ppSectionData));
        if (rpe->ppSectionData == NULL)
            return LOGICAL_MAYBE;
        for (register size_t i = 0; i < wNumSections; ++i) {
            rpe->ppSecHdr[i] = (SECTION_HEADER*)((PTR)&rpe->pNtHdr->OptionalHeader + rpe->pNtHdr->FileHeader.SizeOfOptionalHeader + sizeof(SECTION_HEADER) * i);
            memmove(rpe->ppSecHdr[i], vm->PE.ppSecHdr[i], sizeof(SECTION_HEADER));
            rpe->ppSectionData[i] = (void*)((PTR)rpe->pDosHdr + rpe->ppSecHdr[i]->PointerToRawData);
            memmove(rpe->ppSectionData[i], vm->PE.ppSectionData[i], rpe->ppSecHdr[i]->SizeOfRawData);
        }
    } else {
        rpe->ppSecHdr = NULL;
        rpe->ppSectionData = NULL;
    }
    memset(&rpe->LoadStatus, 0, sizeof(rpe->LoadStatus));
    rpe->LoadStatus = vm->PE.LoadStatus;
    rpe->LoadStatus.Attached = FALSE;
    return LOGICAL_TRUE;
}

/// <summary>
///	Copies an image and fills in cvm with new information, also linked list is
/// adjusted and copied module is inserted after original </summary>
///
/// <param name="rpe">
/// Pointer to VIRTUAL_MODULE containing image </param>
/// <param name="crpe">
/// Pointer to VIRTUAL_MODULE that will recieve copy info </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT/memory error </returns>
LOGICAL EXPORT LIBCALL PlCopyImage(IN VIRTUAL_MODULE* vm, OUT VIRTUAL_MODULE* cvm) {
    PTR MaxPa = 0;
    void* pCopy = NULL;

    if (!LOGICAL_SUCCESS(PlMaxRva(&vm->PE, &MaxPa)))
        return LOGICAL_FALSE;
    pCopy = VirtualAlloc(NULL, MaxPa, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (pCopy == NULL)
        return LOGICAL_MAYBE;
    return PlCopyImageEx(vm, (void*)pCopy, cvm);
}

/// <summary>
///	Copies an image into provided buffer and fills in cvm with new information, also linked list is
/// adjusted and copied module is inserted after original </summary>
///
/// <param name="rpe">
/// Pointer to VIRTUAL_MODULE containing image </param>
/// <param name="pBuffer">
/// Pointer to a buffer of at least PlMaxRva(rpe,) bytes with at least PAGE_READWRITE access
/// <param name="crpe">
/// Pointer to VIRTUAL_MODULE that will recieve copy info </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT/memory error </returns>
LOGICAL EXPORT LIBCALL PlCopyImageEx(IN VIRTUAL_MODULE* vm, IN const void* pBuffer, OUT VIRTUAL_MODULE* cvm) {
    PTR MaxPa = 0;

    // unnecessary per standard, but let's play nice with gaps
    if (!LOGICAL_SUCCESS(PlMaxRva(&vm->PE, &MaxPa)))
        return LOGICAL_FALSE;
    memset((void*)pBuffer, 0, MaxPa);

    cvm->pBaseAddr = (void*)pBuffer;
    cvm->PE.pDosHdr = (DOS_HEADER*)cvm->pBaseAddr;
    memmove(cvm->PE.pDosHdr, vm->pBaseAddr, sizeof(DOS_HEADER));
    cvm->PE.pDosStub = (DOS_STUB*)((PTR)cvm->pBaseAddr + sizeof(DOS_HEADER));
    memmove(cvm->PE.pDosStub, vm->PE.pDosStub, (PTR)cvm->PE.pDosHdr->e_lfanew - sizeof(DOS_HEADER));
    cvm->PE.pNtHdr = (NT_HEADERS*)((PTR)cvm->pBaseAddr + cvm->PE.pDosHdr->e_lfanew);
    memmove(cvm->PE.pNtHdr, vm->PE.pNtHdr, sizeof(NT_HEADERS));
    if (cvm->PE.pNtHdr->FileHeader.NumberOfSections) {
        WORD wNumSections = cvm->PE.pNtHdr->FileHeader.NumberOfSections > MAX_SECTIONS ? MAX_SECTIONS : cvm->PE.pNtHdr->FileHeader.NumberOfSections;
        if (cvm->PE.pNtHdr->FileHeader.NumberOfSections > MAX_SECTIONS) 
            dmsg(TEXT("\nToo many sections to load, only loading %hu of %hu sections!"), MAX_SECTIONS, cvm->PE.pNtHdr->FileHeader.NumberOfSections);

        cvm->PE.ppSecHdr = malloc(wNumSections * sizeof(*cvm->PE.ppSecHdr));
        if (cvm->PE.ppSecHdr == NULL)
            return LOGICAL_MAYBE;
        cvm->PE.ppSectionData = malloc(wNumSections * sizeof(*cvm->PE.ppSectionData));
        if (cvm->PE.ppSectionData == NULL)
            return LOGICAL_MAYBE;
        for (register size_t i = 0; i < wNumSections; ++i) {
            cvm->PE.ppSecHdr[i] = (SECTION_HEADER*)((PTR)&cvm->PE.pNtHdr->OptionalHeader + cvm->PE.pNtHdr->FileHeader.SizeOfOptionalHeader + sizeof(SECTION_HEADER) * i);
            memmove(cvm->PE.ppSecHdr[i], vm->PE.ppSecHdr[i], sizeof(SECTION_HEADER));
            cvm->PE.ppSectionData[i] = (void*)((PTR)cvm->pBaseAddr + cvm->PE.ppSecHdr[i]->VirtualAddress);
            memmove(cvm->PE.ppSectionData[i], vm->PE.ppSectionData[i], cvm->PE.ppSecHdr[i]->Misc.VirtualSize);
        }
    } else {
        cvm->PE.ppSecHdr = NULL;
        cvm->PE.ppSectionData = NULL;
    }
    memset(&cvm->PE.LoadStatus, 0, sizeof(cvm->PE.LoadStatus));
    cvm->PE.LoadStatus = vm->PE.LoadStatus;
    cvm->PE.LoadStatus.Attached = FALSE;
    cvm->Blink = (void*)vm;
    cvm->Flink = vm->Flink;
    vm->Flink = (void*)cvm;
    return LOGICAL_TRUE;
}


/// <summary>
///	Changes a PE's page protections to allow for execution </summary>
///
/// <param name="vm">
/// Pointer to loaded VIRTUAL_MODULE </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT error </returns>
LOGICAL EXPORT LIBCALL PlProtectImage(INOUT VIRTUAL_MODULE* vm) {
    DWORD        dwProtect = 0;
    unsigned int i;

    if (!VirtualProtect(vm->PE.pDosHdr, vm->PE.pNtHdr->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &dwProtect))
        return LOGICAL_FALSE;
    for (i = 0; i < vm->PE.pNtHdr->FileHeader.NumberOfSections; ++i) {
        dwProtect = PlSectionToPageProtection(vm->PE.ppSecHdr[i]->Characteristics);
        // virtualsize will be rounded up to page size, although we could align to SectionAlignment on our own
        if (!VirtualProtect((LPVOID)((PTR)vm->pBaseAddr + vm->PE.ppSecHdr[i]->VirtualAddress), vm->PE.ppSecHdr[i]->Misc.VirtualSize, dwProtect, &dwProtect))
            return LOGICAL_FALSE;
    }
    vm->PE.LoadStatus.Protected = TRUE;
    return LOGICAL_TRUE;
}

/// <summary>
///	Returns a PE to read & write pages for editing </summary>
///
/// <param name="vm">
/// Pointer to loaded VIRTUAL_MODULE </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT error </returns>
LOGICAL EXPORT LIBCALL PlUnprotectImage(INOUT VIRTUAL_MODULE* vm) {
    DWORD        dwProtect = 0;
    unsigned int i;

    if (!VirtualProtect(vm->PE.pDosHdr, vm->PE.pNtHdr->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &dwProtect))
        return LOGICAL_FALSE;
    for (i = 0; i < vm->PE.pNtHdr->FileHeader.NumberOfSections; ++i) {
        // virtualsize will be rounded up to page size, although we could align to SectionAlignment on our own
        if (!VirtualProtect((LPVOID)((PTR)vm->pBaseAddr + vm->PE.ppSecHdr[i]->VirtualAddress), vm->PE.ppSecHdr[i]->Misc.VirtualSize, PAGE_READWRITE, &dwProtect))
            return LOGICAL_FALSE;
    }
    vm->PE.LoadStatus.Protected = FALSE;
    return LOGICAL_TRUE;
}

/// <summary>
///	Frees a mapped image that was allocated </summary>
///
/// <param name="vm">
/// Loaded VIRTUAL_MODULE struct that is not attached </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT/memory error, *vm is zeroed </returns>
LOGICAL EXPORT LIBCALL PlFreeImage(INOUT VIRTUAL_MODULE* vm) {
    VIRTUAL_MODULE *vmNext = NULL,
                   *vmPrev = NULL;

    if (!LOGICAL_SUCCESS(PlFreeFile(&vm->PE)))
        return LOGICAL_FALSE;

    dmsg(TEXT("\nUnlinking PE Image at %p"), vm->pBaseAddr);
    vmPrev = (VIRTUAL_MODULE*)vm->Blink;
    vmNext = (VIRTUAL_MODULE*)vm->Flink;
    if (vmPrev != NULL)
        vmPrev->Flink = vmNext;
    if (vmNext != NULL)
        vmNext->Blink = vmPrev;
    memset(vm, 0, sizeof(*vm));
    return LOGICAL_TRUE;
}

/// <summary>
///	Either frees or detaches a file </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE struct </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT/memory error, *vm is zeroed </returns>
LOGICAL EXPORT LIBCALL PlReleaseImage(INOUT VIRTUAL_MODULE* vm) {
    if (vm->PE.LoadStatus.Attached == TRUE)
        return PlFreeImage(vm);
    else
        return PlDetachImage(vm);
}
