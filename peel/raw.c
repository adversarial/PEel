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

#include "raw.h"

/// <summary>
///	Converts RVA to file offset </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE struct </param>
/// <param name="Rva">
/// Virtual address - module base </param>
/// <param name="Pa">
/// Pointer that will recieve file offset </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL PlRvaToPa(IN const RAW_PE* rpe, IN const PTR Rva, OUT PTR* Pa) {

    if (Rva <= rpe->pNtHdr->OptionalHeader.SizeOfHeaders) {
        *Pa = Rva;
        return LOGICAL_TRUE;
    }
    for (register size_t i = 0; i < rpe->pNtHdr->FileHeader.NumberOfSections; ++i) {
        if (Rva < rpe->ppSecHdr[i]->VirtualAddress + PlAlignUp(rpe->ppSecHdr[i]->SizeOfRawData, rpe->pNtHdr->OptionalHeader.SectionAlignment)
            && Rva >= rpe->ppSecHdr[i]->VirtualAddress) {
                *Pa = Rva - rpe->ppSecHdr[i]->VirtualAddress + rpe->ppSecHdr[i]->PointerToRawData;
                return LOGICAL_TRUE;
        }
    }
    return LOGICAL_FALSE;
}

/// <summary>
///	Converts file offset to RVA </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE struct </param>
/// <param name="Pa">
/// File offset </param>
/// <param name="Pa">
/// Pointer that will recieve RVA </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL PlPaToRva(IN const RAW_PE* rpe, IN const PTR Pa, OUT PTR* Rva) {

    if (Pa <= rpe->pNtHdr->OptionalHeader.SizeOfHeaders) {
        *Rva = Pa;
        return LOGICAL_TRUE;
    }
    for (register size_t i = 0; i < rpe->pNtHdr->FileHeader.NumberOfSections; ++i) {
        if (Pa < rpe->ppSecHdr[i]->PointerToRawData + rpe->ppSecHdr[i]->SizeOfRawData
            && Pa >= rpe->ppSecHdr[i]->PointerToRawData) {
                *Rva = Pa - rpe->ppSecHdr[i]->PointerToRawData + rpe->ppSecHdr[i]->VirtualAddress;
        }
    }
    return LOGICAL_FALSE;
}

/// <summary>
///	Gets a pointer to specified RVA of rpe </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE struct </param>
/// <param name="Rva">
/// Relative virtual address </param>
/// <param name="Ptr">
/// Pointer to data </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL PlGetRvaPtr(IN const RAW_PE* rpe, IN const PTR Rva, OUT PTR* Ptr) {
    PTR Offset = 0;

    // check if it's in headers
    if (Rva > rpe->pNtHdr->OptionalHeader.SizeOfHeaders) {
        // find section
        for (register size_t i = 0; i < rpe->pNtHdr->FileHeader.NumberOfSections; ++i) {
            if (Rva >= rpe->ppSecHdr[i]->VirtualAddress
             && Rva < rpe->ppSecHdr[i]->VirtualAddress + PlAlignUp(rpe->ppSecHdr[i]->Misc.VirtualSize, rpe->pNtHdr->OptionalHeader.SectionAlignment)) {
                Offset = (PTR)rpe->ppSectionData[i] + Rva - rpe->ppSecHdr[i]->VirtualAddress;
                break;
            }
        }
    } else if (Rva < SIZEOF_PE_HEADERS(rpe)) {
        if (Rva < sizeof(DOS_HEADER))
            Offset = (PTR)rpe->pDosHdr + Rva;
        else if (Rva < sizeof(DOS_HEADER) + sizeof(DOS_STUB))
            Offset = (PTR)rpe->pDosStub + Rva - sizeof(DOS_HEADER);
        else if (Rva < rpe->pDosHdr->e_lfanew + sizeof(NT_HEADERS))
            Offset = (PTR)rpe->pNtHdr + Rva - rpe->pDosHdr->e_lfanew;
        else if (Rva < SIZEOF_PE_HEADERS(rpe)) {
            // find correct header
            for (register size_t i = 0; i < rpe->pNtHdr->FileHeader.NumberOfSections; ++i) {
                if (Rva > rpe->pDosHdr->e_lfanew + sizeof(NT_HEADERS) + sizeof(SECTION_HEADER) * i
                 && Rva < rpe->pDosHdr->e_lfanew + sizeof(NT_HEADERS) + sizeof(SECTION_HEADER) * (i + 1)) {
                 Offset = (PTR)rpe->ppSectionData[i] + Rva - rpe->pDosHdr->e_lfanew - sizeof(NT_HEADERS) - sizeof(SECTION_HEADER) * (i - 1);
                 break;
                }
            }
        }
    }
    if (Offset == 0)
        return LOGICAL_FALSE;
    *Ptr = Offset;
    return LOGICAL_TRUE;
}

/// <summary>
///	Gets a pointer to specified PA of rpe </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE struct </param>
/// <param name="Rva">
/// File offset </param>
/// <param name="Ptr">
/// Pointer to data </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL PlGetPaPtr(IN const RAW_PE* rpe, IN const PTR Pa, OUT PTR* Ptr) {
    PTR Rva = 0;

    if (!LOGICAL_SUCCESS(PlPaToRva(rpe, Pa, &Rva)))
        return LOGICAL_FALSE;
    return PlGetRvaPtr(rpe, Rva, Ptr);
}

/// <summary>
///	Writes buffer to specified RVA. Allows for overlapping segments </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE struct </param>
/// <param name="Rva">
/// Relative virtual address </param>
/// <param name="pData">
/// Buffer to write </param>
/// <param name="cbData">
/// Size of buffer </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL PlWriteRva(INOUT RAW_PE* rpe, IN const PTR Rva, IN const void* pData, IN size_t cbData) {
    PTR ptr = 0;

    if (!LOGICAL_SUCCESS(PlGetRvaPtr(rpe, Rva, &ptr)))
        return LOGICAL_FALSE;
    memmove((void*)ptr, pData, cbData);
    return LOGICAL_TRUE;
}

/// <summary>
///	Reads buffer from specified RVA. Use PlWriteRva if pBuffer points to a location within rpe </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE struct </param>
/// <param name="Rva">
/// Relative virtual address </param>
/// <param name="pData">
/// Buffer to write </param>
/// <param name="cbData">
/// Size of buffer </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL PlReadRva(IN const RAW_PE* rpe, IN const PTR Rva, IN void* pBuffer, IN size_t cbBufferMax) {
    PTR ptr = 0;

    if (!LOGICAL_SUCCESS(PlGetRvaPtr(rpe, Rva, &ptr)))
        return LOGICAL_FALSE;
    memmove(pBuffer, (const void*)ptr, cbBufferMax);
    return LOGICAL_TRUE;
}

/// <summary>
///	Writes from pData to specified Pa. Allows overlapping segments </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE struct </param>
/// <param name="Pa">
/// Physical address (file offset) </param>
/// <param name="pData">
/// Pointer to data </param>
/// <param name="cbData">
/// Size of data to copy </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL PlWritePa(INOUT RAW_PE* rpe, IN const PTR Pa, IN const void* pData, IN size_t cbData) {
    PTR Rva = 0;

    if (!LOGICAL_SUCCESS(PlPaToRva(rpe, Pa, &Rva)))
        return LOGICAL_FALSE;
    return PlWriteRva(rpe, Rva, pData, cbData); 
}

/// <summary>
///	Reads buffer from specified Pa. Use PlWritePa if pBuffer points to a location within rpe </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE struct </param>
/// <param name="Pa">
/// Physical address (file offset) </param>
/// <param name="pBuffer">
/// Pointer to a buffer at least cbBufferMax bytes in size</param>
/// <param name="cbBufferMax">
/// Size of buffer </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL PlReadPa(IN const RAW_PE* rpe, IN const PTR Pa, IN void* pBuffer, IN size_t cbBufferMax) {
    PTR Rva = 0;

    if (!LOGICAL_SUCCESS(PlPaToRva(rpe, Pa, &Rva)))
        return LOGICAL_FALSE;
    return PlReadRva(rpe, Rva, pBuffer, cbBufferMax); 
}

/// <summary>
///	Converts Rva to virtual address </summary>
///
/// <param name="vm">
/// Loaded VIRTUAL_MODULE struct </param>
/// <param name="Rva">
/// Relative virtual address </param>
/// <param name="Va">
/// Pointer that will recieve virtual address </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL PlRvaToVa(IN const VIRTUAL_MODULE* vm, IN const PTR Rva, OUT PTR* Va) {

    *Va = (PTR)vm->pBaseAddr + Rva;
    return LOGICAL_TRUE;
}

/// <summary>
///	Converts file offset to virtual address </summary>
///
/// <param name="rpe">
/// Loaded VIRTUAL_MODULE struct </param>
/// <param name="Pa">
/// File offset </param>
/// <param name="Va">
/// Pointer that will recieve virtual address </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL PlPaToVa(IN const VIRTUAL_MODULE* vm, IN const PTR Pa, OUT PTR* Va) {
    PTR Rva = 0;

    if (!LOGICAL_SUCCESS(PlPaToRva(&vm->PE, Pa, &Rva)))
        return LOGICAL_FALSE;
    return PlRvaToVa(vm, Rva, Va);
}

/// <summary>
///	Calculates aligned virtual size </summary>
///
/// <param name="vpe">
/// Loaded RAW_PE </param>
/// <param name="Pa">
/// Pointer that will recieve file size </param>
///
/// <returns>
/// LOGICAL_TRUE always (no error checking) </returns>
LOGICAL EXPORT LIBCALL PlMaxPa(IN const RAW_PE* rpe, OUT PTR* MaxPa) {
    PTR dwLargeAddr = 0;
    
    *MaxPa = rpe->pNtHdr->OptionalHeader.SizeOfHeaders;
    if (!rpe->pNtHdr->FileHeader.NumberOfSections)
        return LOGICAL_TRUE;
    for (register size_t i = 0; i < rpe->pNtHdr->FileHeader.NumberOfSections; ++i) {
        dwLargeAddr = rpe->ppSecHdr[i]->PointerToRawData + rpe->ppSecHdr[i]->SizeOfRawData;
        *MaxPa = dwLargeAddr > *MaxPa ? dwLargeAddr : *MaxPa; // max(dwLargeAddr, *MaxPa) 
    }
    return LOGICAL_TRUE;
}

/// <summary>
///	Calculates aligned virtual size </summary>
///
/// <param name="vpe">
/// Loaded RAW_PE </param>
/// <param name="Rva">
/// Pointer that will recieve virtual size </param>
///
/// <returns>
/// LOGICAL_TRUE always (no error checking) </returns>
LOGICAL EXPORT LIBCALL PlMaxRva(IN const RAW_PE* rpe, OUT PTR* MaxRva) {
    PTR dwLargeAddr = 0;
    
    *MaxRva = rpe->pNtHdr->OptionalHeader.SizeOfHeaders;
    if (!rpe->pNtHdr->FileHeader.NumberOfSections)
        return LOGICAL_TRUE;
    for (register size_t i = 0; i < rpe->pNtHdr->FileHeader.NumberOfSections; ++i) {
        dwLargeAddr = rpe->ppSecHdr[i]->VirtualAddress + PlAlignUp(rpe->ppSecHdr[i]->Misc.VirtualSize, rpe->pNtHdr->OptionalHeader.SectionAlignment);
        *MaxRva = dwLargeAddr > *MaxRva ? dwLargeAddr : *MaxRva; // max(dwLargeAddr, *MaxRva) 
    }
    return LOGICAL_TRUE;
}

/// <summary>
///	Loads import list into rpe->pImport </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE error, LOGICAL_MAYBE on crt/memory allocation error </returns>
LOGICAL EXPORT LIBCALL PlEnumerateImports(INOUT RAW_PE* rpe) {
    IMPORT_DESCRIPTOR   *iidDesc = NULL;
    THUNK_DATA        *tdIat = NULL;
    IMPORT_NAME         *inName = NULL;
    IMPORT_LIBRARY    *pImport = NULL;
    IMPORT_ITEM       *pII = NULL;
    
    // do we even have to do imports?
    if (!rpe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size
     && !rpe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
        return LOGICAL_TRUE;
    rpe->pImport = (IMPORT_LIBRARY*)calloc(1, sizeof(IMPORT_LIBRARY));
    if (rpe->pImport == NULL)
        return LOGICAL_MAYBE;
    pImport = rpe->pImport;
    iidDesc = (IMPORT_DESCRIPTOR*)((PTR)rpe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (!LOGICAL_SUCCESS(PlGetRvaPtr(rpe, (PTR)iidDesc, (PTR*)&iidDesc)))
        return LOGICAL_FALSE;
    for (; iidDesc->Characteristics; ++iidDesc) {
        pImport->Library = (char*)iidDesc->Name;
        if (!LOGICAL_SUCCESS(PlGetRvaPtr(rpe, (PTR)pImport->Library, (PTR*)&pImport->Library)))
            return LOGICAL_FALSE;
        tdIat = (THUNK_DATA*)iidDesc->FirstThunk;
        if (!LOGICAL_SUCCESS(PlGetRvaPtr(rpe, (PTR)tdIat, (PTR*)&tdIat)))
            return LOGICAL_FALSE;
        pII = (IMPORT_ITEM*)calloc(1, sizeof(IMPORT_ITEM));
        if (pII == NULL)
            return LOGICAL_MAYBE;
        pImport->iiImportList = pII;
        for (; tdIat->u1.Function; ++tdIat) {
            if (tdIat->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                pII->Ordinal = (char*)tdIat->u1.Ordinal;
            else {
                inName = (IMPORT_NAME*)tdIat->u1.AddressOfData;
                if (!LOGICAL_SUCCESS(PlGetRvaPtr(rpe, (PTR)inName, (PTR*)&inName)))
                    return LOGICAL_FALSE;
                pII->Name = (char*)inName->Name;
            }
            pII->dwItemPtr = (PTR*)&tdIat->u1.AddressOfData;
            THUNK_DATA* tdNext = tdIat + 1;
            if (tdNext->u1.Function) {
                pII->Flink = calloc(1, sizeof(IMPORT_ITEM));
                if (pII->Flink == NULL)
                    return LOGICAL_MAYBE;
                pII = (IMPORT_ITEM*)pII->Flink;
            }
        }
        if (iidDesc[1].Characteristics) {   // check if next item is there (to allocate)
            pImport->Flink = calloc(1, sizeof(IMPORT_LIBRARY));   // fix extra allocation issue
            if (pImport->Flink == NULL)
                return LOGICAL_MAYBE;
            pImport = (IMPORT_LIBRARY*)pImport->Flink;
        }
    }
    return LOGICAL_TRUE;
}

/// <summary>
///	Frees import lists in rpe->pImport </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE error, LOGICAL_MAYBE on crt/memory allocation error </returns>
LOGICAL EXPORT LIBCALL PlFreeEnumeratedImports(INOUT RAW_PE* rpe) {
    IMPORT_LIBRARY  *pImport = NULL,
                      *pImportNext = NULL;
    IMPORT_ITEM     *pII = NULL,
                      *pIINext = NULL;

    if (rpe->pImport == NULL)
        return LOGICAL_FALSE;
    
    for (pImport = rpe->pImport; pImport != NULL; pImport = pImportNext) {
        for (pII = pImport->iiImportList; pII != NULL; pII = pIINext) {
            pIINext = (IMPORT_ITEM*)pII->Flink;
            free(pII);
        }
        pImportNext = (IMPORT_LIBRARY*)pImport->Flink;
        free(pImport);
    }
    rpe->pImport = NULL;
    return LOGICAL_TRUE;
}

/// <summary>
///	Loads export list into rpe->pExport </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE error, LOGICAL_MAYBE on crt/memory allocation error </returns>
LOGICAL EXPORT LIBCALL PlEnumerateExports(INOUT RAW_PE* rpe) {
    EXPORT_DIRECTORY* pED = NULL;
    EXPORT_LIST* pExport = NULL;

    PTR* ppszNames = NULL;
    DWORD* ppdwOrdinals = NULL;
    PTR* ppFunctionPtrs = NULL;

    // do we even have exports?
    if (!rpe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size
     && !rpe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
        return LOGICAL_TRUE;
    rpe->pExport = (EXPORT_LIST*)calloc(1, sizeof(EXPORT_LIST));
    if (rpe->pExport == NULL)
        return LOGICAL_MAYBE;
    pExport = rpe->pExport;
    pED = (EXPORT_DIRECTORY*)rpe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!LOGICAL_SUCCESS(PlGetRvaPtr(rpe, (PTR)pED, (PTR*)&pED)))
        return LOGICAL_FALSE;
    ppszNames = (PTR*)pED->AddressOfNames;
    if (!LOGICAL_SUCCESS(PlGetRvaPtr(rpe, (PTR)ppszNames, (PTR*)&ppszNames)))
        return LOGICAL_FALSE;
    ppdwOrdinals = (DWORD*)pED->AddressOfNameOrdinals;
    if (!LOGICAL_SUCCESS(PlGetRvaPtr(rpe, (PTR)ppdwOrdinals, (PTR*)&ppdwOrdinals)))
        return LOGICAL_FALSE;
    ppFunctionPtrs = (PTR*)pED->AddressOfFunctions;
    if (!LOGICAL_SUCCESS(PlGetRvaPtr(rpe, (PTR)ppFunctionPtrs, (PTR*)&ppFunctionPtrs)))
        return LOGICAL_FALSE;
    // wierd solution but theoretically one could be bigger so we'll pick the biggest one
    for (register size_t i = 0; i < (pED->NumberOfFunctions > pED->NumberOfNames ? pED->NumberOfFunctions : pED->NumberOfNames); ++i) {
        pExport->Name = (char*)*ppszNames++;
        PlGetRvaPtr(rpe, (PTR)pExport->Name, (PTR*)&pExport->Name);
        pExport->Ordinal = (char*)*ppdwOrdinals++;
        PlGetRvaPtr(rpe, (PTR)pExport->Ordinal, (PTR*)&pExport->Ordinal);
        pExport->dwItemPtr = (PTR*)ppFunctionPtrs++;
        pExport->Flink = calloc(1, sizeof(EXPORT_LIST));
        if (pExport->Flink == NULL)
            return LOGICAL_MAYBE;
        pExport = (EXPORT_LIST*)pExport->Flink;
    }
    return LOGICAL_TRUE;
}

/// <summary>
///	Frees export list in rpe->pExport </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE error, LOGICAL_MAYBE on crt/memory allocation error </returns>
LOGICAL EXPORT LIBCALL PlFreeEnumeratedExports(INOUT RAW_PE* rpe) {
    EXPORT_LIST *pExport = NULL,
                  *pExportNext = NULL;

    if (rpe->pExport == NULL)
        return LOGICAL_FALSE;
    for (pExport = rpe->pExport; pExport != NULL; pExport = (EXPORT_LIST*)pExportNext) {
        pExportNext = (EXPORT_LIST*)pExport->Flink;
        free(pExport);
    }
    rpe->pExport = NULL;
    return LOGICAL_TRUE;
}

/// <summary>
///	Performs relocations on RAW_PE </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE </param>
/// <param name="dwOldBase">
/// Current base address that rpe is relocated to, most likely rpe->pNtHdr->OptionalHeader->ImageBase
/// <param name="dwNewBase">
/// Base to relocate to, most likely rpe->pDosHdr
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE error, LOGICAL_MAYBE on crt/memory allocation error </returns>
LOGICAL EXPORT LIBCALL PlRelocate(INOUT RAW_PE* rpe, IN const PTR dwOldBase, IN const PTR dwNewBase) {
    BASE_RELOCATION *brReloc = NULL;
    RELOC_ITEM      *riItem = NULL;
    PTR	        dwDelta = 0;
    PTR             dwRelocAddr = 0,
                    dwRelocBase = 0;
	DWORD	        cbRelocSection = 0,
			        dwItems = 0;

    // do we even have relocations?
	dwDelta = dwNewBase - dwOldBase;
	if (!dwDelta
	 || !rpe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
	 || !rpe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
		return LOGICAL_TRUE;

	cbRelocSection = rpe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	brReloc = (BASE_RELOCATION*)(rpe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    if(!LOGICAL_SUCCESS(PlGetRvaPtr(rpe, (PTR)brReloc, (PTR*)&brReloc)))
        return LOGICAL_FALSE;
	for (dwRelocBase = (PTR)brReloc; (PTR)brReloc < dwRelocBase + cbRelocSection; brReloc = (BASE_RELOCATION*)((PTR)brReloc + brReloc->SizeOfBlock)) {
		for (riItem = (RELOC_ITEM*)((PTR)brReloc + sizeof(BASE_RELOCATION)), dwItems = brReloc->SizeOfBlock / sizeof(RELOC_ITEM); dwItems; --dwItems, ++riItem) {
			switch(riItem->Type) {
				case IMAGE_REL_BASED_HIGHLOW:
                    dwRelocAddr = brReloc->VirtualAddress + riItem->Offset;
                    if (!LOGICAL_SUCCESS(PlGetRvaPtr(rpe, dwRelocAddr, &dwRelocAddr)))
                        return LOGICAL_FALSE;
					*(PTR32*)dwRelocAddr += dwDelta;
				case IMAGE_REL_BASED_ABSOLUTE:
					// dwItems = 1;				// end the loop (rest is padding)
                    // edit - leaving because windows loader doesn't do this
				default:
					break;						// I don't feel like throwing an error
		    }
	    }
    }
	rpe->LoadStatus.Relocated = TRUE;
	return LOGICAL_TRUE;
}

/// <summary>
///	Calculates PE header checksum for file </summary>
///
/// <param name="vpe">
/// Pointer to RAW_PE containing loaded file </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, 
/// LOGICAL_MAYBE on CRT/memory error </returns>
LOGICAL EXPORT LIBCALL PlCalculateChecksum(INOUT RAW_PE* rpe, OUT DWORD* dwChecksum) {
    PTR       dwMaxPa = 0;
    LOGICAL     lResult = LOGICAL_FALSE;
    USHORT     *pCurrBlock = NULL;
    DWORD       dwProt = 0,
                dwOldChecksum = 0;

    lResult = PlMaxPa(rpe, &dwMaxPa);
    if (!LOGICAL_SUCCESS(lResult))
        return lResult;
    // some wierd shit in ntdll.RtlImageNtHeaderEx to get NT_HEADERS*
    // arg3 ends up being &NT_HEADERS.Signature
        if (rpe->pDosHdr != NULL || rpe->pDosHdr == INVALID_HANDLE_VALUE || dwMaxPa != 0) {
            *dwChecksum = 0;
        // RtlImageNtHeadersEx(?, Base, Size, Out)
            if (rpe->pDosHdr->e_magic != IMAGE_DOS_SIGNATURE || (PTR)rpe->pDosHdr->e_lfanew > dwMaxPa)
                return LOGICAL_FALSE;
            if (rpe->pNtHdr == NULL || rpe->pNtHdr == INVALID_HANDLE_VALUE || rpe->pNtHdr->FileHeader.SizeOfOptionalHeader == 0) {
                return LOGICAL_FALSE;
            }
        // and now I'm bored of literally translating.
        // welp here's the "optimized" version
            if (!VirtualProtect((LPVOID)&rpe->pNtHdr->OptionalHeader.CheckSum, sizeof(rpe->pNtHdr->OptionalHeader.CheckSum), PAGE_READWRITE, &dwProt))
                return LOGICAL_FALSE;
            dwOldChecksum = rpe->pNtHdr->OptionalHeader.CheckSum;
        // checksumming must be done with 0'd old one (how would we checksum the future?)
            rpe->pNtHdr->OptionalHeader.CheckSum = 0;
            
        // micro$hit had some fancy optimi-say-shuns [southern accent here]
        // well fuck that, maybe -O2 will help
            pCurrBlock = (USHORT*)rpe->pDosHdr;
            for (register size_t i = 0; i < (rpe->pDosHdr->e_cparhdr << 4) / sizeof(USHORT); ++i) {
                *dwChecksum = *(USHORT*)pCurrBlock++ + *dwChecksum;
                *dwChecksum = *(USHORT*)dwChecksum + (*dwChecksum >> (sizeof(USHORT) * CHAR_BIT));
            }
            pCurrBlock = (USHORT*)rpe->pNtHdr;
            for (register size_t i = 0; i < sizeof(NT_HEADERS) / sizeof(USHORT); ++i) {
                *dwChecksum = *(USHORT*)pCurrBlock++ + *dwChecksum;
				*dwChecksum = *(USHORT*)dwChecksum + (*dwChecksum >> (sizeof(USHORT) * CHAR_BIT));
            }
            for (register size_t k = 0; k < rpe->pNtHdr->FileHeader.NumberOfSections; ++k) {
                pCurrBlock = (USHORT*)rpe->ppSectionData[k];
                for (register size_t i = 0; i < rpe->ppSecHdr[k]->SizeOfRawData / sizeof(USHORT); ++i) { // at least sizeofrawdata bytes should be there
                    *dwChecksum = *(USHORT*)pCurrBlock++ + *dwChecksum;
                    *dwChecksum = *(USHORT*)dwChecksum + (*dwChecksum >> (sizeof(USHORT) * CHAR_BIT));
                }
            }
			*dwChecksum = (*dwChecksum & (USHORT)~0) + (*dwChecksum >> (sizeof(USHORT) * CHAR_BIT));
            if (dwMaxPa & 1) // for the idiots who use 1byte FileAlignment
                *dwChecksum += (uint8_t)*((uint8_t*)rpe->pDosHdr + dwMaxPa - 1);
            *dwChecksum += dwMaxPa; // this took like 10 minutes to figure out what I was missing
            dmsg("PE at %08lx has checksum %lx", rpe->pDosHdr, *dwChecksum);
        // microsoft doesn't restore the old checksum tho
            rpe->pNtHdr->OptionalHeader.CheckSum = dwOldChecksum; 
            if (!VirtualProtect((LPVOID)&rpe->pNtHdr->OptionalHeader.CheckSum, sizeof(rpe->pNtHdr->OptionalHeader.CheckSum), dwProt, &dwProt))
                return LOGICAL_FALSE;
            return LOGICAL_TRUE;
        }
    return LOGICAL_FALSE;
}