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

LOGICAL EXPORT LIBCALL HlpLoadAndBurn(IN const void* pLibrary, OUT VIRTUAL_MODULE* vmOut) {
    RAW_PE         rpeIn = {0};
    VIRTUAL_MODULE vmIn = {0};
    LOGICAL          lResult = LOGICAL_FALSE;

    if (!LOGICAL_SUCCESS(PlAttachFile(pLibrary, &rpeIn)))
        return LOGICAL_FALSE;
    if (!LOGICAL_SUCCESS(PlFileToImage(&rpeIn, &vmIn)))
        return LOGICAL_FALSE;
    PlDetachFile(&rpeIn);
    lResult = HlpLoadAndBurnEx(&vmIn, vmOut);
    PlFreeImage(&vmIn);
    return lResult;
}

LOGICAL EXPORT LIBCALL HlpLoadAndBurnEx(IN const VIRTUAL_MODULE* vmIn, OUT VIRTUAL_MODULE* vmOut) {
    wchar_t          wzSysDir[MAX_SYSPATH] = {0};
    HANDLE           hSearch = NULL,
                     hFile = NULL,
                     hFileMapping = NULL;
    void            *pFile;
    WIN_FIND_DATAW wfdFile = {0};
    RAW_PE         rpeTarget = {0};
    VIRTUAL_MODULE vmTarget = {0};
    PTR            dwMaxRvaTarget = 0,
                     dwMaxRvaPayload = 0;
    HMODULE          hTarget = NULL;
    LOGICAL          lResult = LOGICAL_FALSE;   
    DWORD            dwRand = 0;

    if (!LOGICAL_SUCCESS(PlMaxRva(&vmIn->PE, &dwMaxRvaPayload)))
        return LOGICAL_FALSE;

  // set extended max length
    memcpy(wzSysDir, L"\\\\?\\", 4 * sizeof(wchar_t));
    GetSystemDirectoryW(wzSysDir + 4, MAX_SYSPATH - 4);

  // now search for a decent sized file
    hSearch = FindFirstFileW(wzSysDir, &wfdFile);
    if (hSearch == INVALID_HANDLE_VALUE)
        return LOGICAL_FALSE;
    do {
      // one two, skip a few
        if (__rdtsc() & 1)
            continue;
      // gigantic nest so I don't have a million CloseHandle calls
      // yes, I know how bad it is
        if (wfdFile.nFileSizeLow == 0)
            continue;   // we can't map empty files
        hFile = CreateFileW(wfdFile.cFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            hFileMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
            if (hFileMapping != NULL) {
                pFile = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
                if (pFile != NULL) {
                  // now check if decent size
                    if (LOGICAL_SUCCESS(PlAttachFile(pFile, &rpeTarget))) {   
                        PlMaxRva(&rpeTarget, &dwMaxRvaTarget);
                      // we can close everything now seeing as we're done checking
                        PlDetachFile(&rpeTarget);
                        UnmapViewOfFile(pFile);
                        CloseHandle(hFileMapping);
                        CloseHandle(hFile);
                        if (dwMaxRvaTarget >= dwMaxRvaPayload) {
                          // we're clear to load our file
                            hTarget = LoadLibraryW(wfdFile.cFileName);
                            if (hTarget != NULL) {
                                PlAttachImage(hTarget, &vmTarget);
                                lResult = HlpReplaceImage(&vmTarget, (VIRTUAL_MODULE*)vmIn, vmOut);
                                PlDetachImage(&vmTarget);
                                if (lResult == LOGICAL_TRUE) 
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        if (pFile != NULL)
            UnmapViewOfFile(pFile);
        if (hFileMapping != NULL)
            CloseHandle(hFileMapping);
        if (hFile != INVALID_HANDLE_VALUE)
            CloseHandle(hFile);
        pFile = NULL;
        hFileMapping = NULL;
        hFile = INVALID_HANDLE_VALUE;
    } while(FindNextFileW(hSearch, &wfdFile));
    if (pFile != NULL)
        UnmapViewOfFile(pFile);
    if (hFileMapping != NULL)
        CloseHandle(hFileMapping);
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    FindClose(hSearch);
    return lResult;
}

LOGICAL EXPORT LIBCALL HlpFreeBurnedLibrary(INOUT VIRTUAL_MODULE* vm) {
    FreeLibrary((HMODULE)vm->pBaseAddr);
    PlDetachImage(vm);
    return LOGICAL_TRUE;
}

LOGICAL EXPORT LIBCALL HlpResolveImportsWinApi(INOUT VIRTUAL_MODULE* vm) {
    LOGICAL lResult = LOGICAL_FALSE;

    IMPORT_LIBRARY*  pImportLibrary = NULL;
    IMPORT_ITEM*     pImportItem = NULL;
    LDR_MODULE*      plmModule = NULL;
    VIRTUAL_MODULE   vmIn = {0};

    wchar_t            wzName[0x100] = {0};
    
    if (vm->PE.LoadStatus.Imported)
        return LOGICAL_TRUE;
    if (vm->PE.pImport == NULL) {
        lResult = PlEnumerateImports(&vm->PE);
        if (!LOGICAL_SUCCESS(lResult))
            return lResult;
    }
    for (pImportLibrary = vm->PE.pImport; pImportLibrary->Flink != NULL; pImportLibrary = (IMPORT_LIBRARY*)pImportLibrary->Flink) {
        mbstowcs(wzName, pImportLibrary->Library, 0x100);
        plmModule = KpGetLdrModule(wzName);
        if (plmModule == NULL) { // it's not loaded yet
            PlAttachImage(LoadLibraryW(wzName), &vmIn);
        } else
            PlAttachImage(plmModule->BaseAddress, &vmIn);
        for (pImportItem = pImportLibrary->iiImportList; pImportItem->Flink != NULL; pImportItem = (IMPORT_ITEM*)pImportItem->Flink) {
            if (pImportItem->Name)
                *pImportItem->dwItemPtr = (PTR)GetProcAddress((HMODULE)plmModule->BaseAddress, pImportItem->Name);
            else if (pImportItem->Ordinal)
                *pImportItem->dwItemPtr = (PTR)GetProcAddress((HMODULE)plmModule->BaseAddress, pImportItem->Ordinal);
        }
    }

    vm->PE.LoadStatus.Imported = TRUE;
    return LOGICAL_TRUE;
}

LOGICAL EXPORT LIBCALL HlpResolveImports(INOUT VIRTUAL_MODULE* vm) {
    LOGICAL           lResult = LOGICAL_FALSE;
    IMPORT_LIBRARY* pImportLibrary = NULL;
    IMPORT_ITEM*    pImportItem = NULL;
    LDR_MODULE*     plmModule = NULL;
    wchar_t           wzName[0x100] = {0};
    VIRTUAL_MODULE  vmIn = {0};

    if (vm->PE.LoadStatus.Imported)
        return LOGICAL_TRUE;
    if (vm->PE.pImport == NULL) {
        lResult = PlEnumerateImports(&vm->PE);
        if (!LOGICAL_SUCCESS(lResult))
            return lResult;
    }
    for (pImportLibrary = vm->PE.pImport; pImportLibrary->Flink != NULL; pImportLibrary = (IMPORT_LIBRARY*)pImportLibrary->Flink) {
        mbstowcs(wzName, pImportLibrary->Library, 0x100);
        plmModule = KpGetLdrModule(wzName);
        if (plmModule == NULL) { // it's not loaded yet
            PlAttachImage(LoadLibraryW(wzName), &vmIn);
        } else
            PlAttachImage(plmModule->BaseAddress, &vmIn);
        for (pImportItem = pImportLibrary->iiImportList; pImportItem->Flink != NULL; pImportItem = (IMPORT_ITEM*)pImportItem->Flink) {

        }
    }

    vm->PE.LoadStatus.Imported = TRUE;
    return LOGICAL_TRUE;
}

LOGICAL EXPORT LIBCALL HlpReplaceImage(INOUT VIRTUAL_MODULE* vmTarget, IN VIRTUAL_MODULE* vmReplacement, OUT VIRTUAL_MODULE* vmClone) {
    PTR         dwMaxRvaTarget = 0,
                  dwMaxRvaReplacement = 0;
    PEB          *pPeb;
    LDR_MODULE *plmModule;
    wchar_t       wzName[9] = {0},
                  wzNameReplacement[9] = {0};

    if (!LOGICAL_SUCCESS(PlMaxRva(&vmTarget->PE, &dwMaxRvaTarget))
     || !LOGICAL_SUCCESS(PlMaxRva(&vmReplacement->PE, &dwMaxRvaReplacement)))
        return LOGICAL_FALSE;

    pPeb = (PEB*)KpGetCurrentPeb();
    if (pPeb == NULL) // not really possible unless not on intel
        return LOGICAL_FALSE;

    mbstowcs(wzName, vmTarget->cName, 8);
    mbstowcs(wzNameReplacement, vmReplacement->cName, 8);

  // WARNING undocumented WARNING
    plmModule = KpGetLdrModule(wzName);
    if (plmModule == NULL)
        return LOGICAL_FALSE;
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
  // now update vmReplacement and copy the image
    PlCopyImageEx(vmReplacement, vmTarget->pBaseAddr, vmClone);
    PlRelocate(&vmClone->PE, (PTR)vmReplacement->pBaseAddr, (PTR)vmTarget->pBaseAddr);
    PlProtectImage(vmClone);
    PlDetachImage(vmTarget);
    vmClone->PE.LoadStatus.Relocated = TRUE;
    vmClone->PE.LoadStatus.Protected = TRUE;
    return LOGICAL_TRUE;
}

LOGICAL EXPORT LIBCALL HlpAddSectionHeader(INOUT RAW_PE* rpe, IN SECTION_HEADER* pshIn) {
    int iLowSec = 0;
    PTR dwLowAddr = rpe->ppSecHdr[0]->PointerToRawData;
    SECTION_HEADER *pshNew = NULL;

    for (register size_t i = 0; i < rpe->pNtHdr->FileHeader.NumberOfSections; ++i) {
        if (rpe->ppSecHdr[i]->PointerToRawData < dwLowAddr) {
            dwLowAddr = rpe->ppSecHdr[i]->PointerToRawData;
            iLowSec = i;
        }
    }

    if (SIZEOF_PE_HEADERS(rpe) + sizeof(SECTION_HEADER) > rpe->ppSecHdr[iLowSec]->PointerToRawData) { // we have to shift the sections
        rpe->pNtHdr->OptionalHeader.SizeOfHeaders += rpe->pNtHdr->OptionalHeader.FileAlignment;       // to the next gap

        for (register size_t i = 0; i < rpe->pNtHdr->FileHeader.NumberOfSections; ++i) {
            rpe->ppSecHdr[i]->PointerToRawData += rpe->pNtHdr->OptionalHeader.FileAlignment;
            rpe->ppSecHdr[i]->VirtualAddress += rpe->pNtHdr->OptionalHeader.SectionAlignment;
        }

        memmove((void*)((PTR)rpe->pDosHdr + rpe->ppSecHdr[iLowSec]->PointerToRawData, (void*)((PTR)dwLowAddr + (PTR)rpe->pDosHdr), 
    }
    
    pshNew = (SECTION_HEADER*)SIZEOF_PE_HEADERS(rpe); // get end of headers
    memcpy(pshNew, pshIn, sizeof(SECTION_HEADER));

    ++rpe->pNtHdr->FileHeader.NumberOfSections;       // adjust relevant values
}