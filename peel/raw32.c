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

#include "raw32.h"

/// <summary>
///	Converts RVA to file offset </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE32 struct </param>
/// <param name="Rva">
/// Virtual address - module base </param>
/// <param name="Pa">
/// Pointer that will recieve file offset </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL MrRvaToPa32(IN const RAW_PE32* rpe, IN const PTR32 Rva, OUT PTR32* Pa) {
    unsigned int i;

    if (Rva <= rpe->pINH->OptionalHeader.SizeOfHeaders) {
        *Pa = Rva;
        return LOGICAL_TRUE;
    }
    for (i = 0; i < rpe->pINH->FileHeader.NumberOfSections; ++i) {
        if (Rva < rpe->ppISH[i]->VirtualAddress + MrAlignUp32(rpe->ppISH[i]->SizeOfRawData, rpe->pINH->OptionalHeader.SectionAlignment)
            && Rva >= rpe->ppISH[i]->VirtualAddress) {
                *Pa = Rva - rpe->ppISH[i]->VirtualAddress + rpe->ppISH[i]->PointerToRawData;
                return LOGICAL_TRUE;
        }
    }
    return LOGICAL_FALSE;
}

/// <summary>
///	Converts file offset to RVA </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE32 struct </param>
/// <param name="Pa">
/// File offset </param>
/// <param name="Pa">
/// Pointer that will recieve RVA </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL MrPaToRva32(IN const RAW_PE32* rpe, IN const PTR32 Pa, OUT PTR32* Rva) {
    unsigned int i;

    if (Pa <= rpe->pINH->OptionalHeader.SizeOfHeaders) {
        *Rva = Pa;
        return LOGICAL_TRUE;
    }
    for (i = 0; i < rpe->pINH->FileHeader.NumberOfSections; ++i) {
        if (Pa < rpe->ppISH[i]->PointerToRawData + rpe->ppISH[i]->SizeOfRawData
            && Pa >= rpe->ppISH[i]->PointerToRawData) {
                *Rva = Pa - rpe->ppISH[i]->PointerToRawData + rpe->ppISH[i]->VirtualAddress;
        }
    }
    return LOGICAL_FALSE;
}

/// <summary>
///	Gets a pointer to specified RVA of rpe </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE32 struct </param>
/// <param name="Rva">
/// Relative virtual address </param>
/// <param name="Ptr">
/// Pointer to data </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL MrGetRvaPtr32(IN const RAW_PE32* rpe, IN const PTR32 Rva, OUT PTR* Ptr) {
    PTR Offset = 0;
    unsigned int i;

    // check if it's in headers
    if (Rva > rpe->pINH->OptionalHeader.SizeOfHeaders) {
        // find section
        for (i = 0; i < rpe->pINH->FileHeader.NumberOfSections; ++i) {
            if (Rva >= rpe->ppISH[i]->VirtualAddress
             && Rva < rpe->ppISH[i]->VirtualAddress + MrAlignUp32(rpe->ppISH[i]->Misc.VirtualSize, rpe->pINH->OptionalHeader.SectionAlignment)) {
                Offset = (PTR)rpe->ppSectionData[i] + Rva - rpe->ppISH[i]->VirtualAddress;
                break;
            }
        }
    } else if (Rva < SIZEOF_PE_HEADERS32(rpe)) {
        if (Rva < sizeof(DOS_HEADER))
            Offset = (PTR)rpe->pIDH + Rva;
        else if (Rva < sizeof(DOS_HEADER) + sizeof(DOS_STUB))
            Offset = (PTR)rpe->pIDS + Rva - sizeof(DOS_HEADER);
        else if (Rva < rpe->pIDH->e_lfanew + sizeof(NT_HEADERS32))
            Offset = (PTR)rpe->pINH + Rva - rpe->pIDH->e_lfanew;
        else if (Rva < SIZEOF_PE_HEADERS32(rpe)) {
            // find correct header
            for (i = 0; i < rpe->pINH->FileHeader.NumberOfSections; ++i) {
                if (Rva > rpe->pIDH->e_lfanew + sizeof(NT_HEADERS32) + sizeof(SECTION_HEADER) * i
                 && Rva < rpe->pIDH->e_lfanew + sizeof(NT_HEADERS32) + sizeof(SECTION_HEADER) * (i + 1)) {
                 Offset = (PTR)rpe->ppSectionData[i] + Rva - rpe->pIDH->e_lfanew - sizeof(NT_HEADERS32) - sizeof(SECTION_HEADER) * (i - 1);
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
/// Loaded RAW_PE32 struct </param>
/// <param name="Rva">
/// File offset </param>
/// <param name="Ptr">
/// Pointer to data </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL MrGetPaPtr32(IN const RAW_PE32* rpe, IN const PTR32 Pa, OUT PTR* Ptr) {
    PTR32 Rva = 0;
    if (!LOGICAL_SUCCESS(MrPaToRva32(rpe, Pa, &Rva)))
        return LOGICAL_FALSE;
    return MrGetRvaPtr32(rpe, Rva, Ptr);
}

/// <summary>
///	Writes buffer to specified RVA. Allows for overlapping segments </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE32 struct </param>
/// <param name="Rva">
/// Relative virtual address </param>
/// <param name="pData">
/// Buffer to write </param>
/// <param name="cbData">
/// Size of buffer </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL MrWriteRva32(INOUT RAW_PE32* rpe, IN const PTR32 Rva, IN const void* pData, IN size_t cbData) {
    PTR ptr;

    if (!LOGICAL_SUCCESS(MrGetRvaPtr32(rpe, Rva, &ptr)))
        return LOGICAL_FALSE;
    memmove((void*)ptr, pData, cbData);
    return LOGICAL_TRUE;
}

/// <summary>
///	Reads buffer from specified RVA. Use MrWriteRva32 if pBuffer points to a location within rpe </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE32 struct </param>
/// <param name="Rva">
/// Relative virtual address </param>
/// <param name="pData">
/// Buffer to write </param>
/// <param name="cbData">
/// Size of buffer </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL MrReadRva32(IN const RAW_PE32* rpe, IN const PTR32 Rva, IN void* pBuffer, IN size_t cbBufferMax) {
    PTR ptr;

    if (!LOGICAL_SUCCESS(MrGetRvaPtr32(rpe, Rva, &ptr)))
        return LOGICAL_FALSE;
    memmove(pBuffer, (const void*)ptr, cbBufferMax);
    return LOGICAL_TRUE;
}

/// <summary>
///	Writes from pData to specified Pa. Allows overlapping segments </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE32 struct </param>
/// <param name="Pa">
/// Physical address (file offset) </param>
/// <param name="pData">
/// Pointer to data </param>
/// <param name="cbData">
/// Size of data to copy </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL MrWritePa32(INOUT RAW_PE32* rpe, IN const PTR32 Pa, IN const void* pData, IN size_t cbData) {
    PTR Rva;

    if (!LOGICAL_SUCCESS(MrPaToRva32(rpe, Pa, &Rva)))
        return LOGICAL_FALSE;
    return MrWriteRva32(rpe, Rva, pData, cbData); 
}

/// <summary>
///	Reads buffer from specified Pa. Use MrWritePa32 if pBuffer points to a location within rpe </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE32 struct </param>
/// <param name="Pa">
/// Physical address (file offset) </param>
/// <param name="pBuffer">
/// Pointer to a buffer at least cbBufferMax bytes in size</param>
/// <param name="cbBufferMax">
/// Size of buffer </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL MrReadPa32(IN const RAW_PE32* rpe, IN const PTR32 Pa, IN void* pBuffer, IN size_t cbBufferMax) {
    PTR Rva;

    if (!LOGICAL_SUCCESS(MrPaToRva32(rpe, Pa, &Rva)))
        return LOGICAL_FALSE;
    return MrReadRva32(rpe, Rva, pBuffer, cbBufferMax); 
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
LOGICAL EXPORT LIBCALL MrRvaToVa32(IN const VIRTUAL_MODULE32* vm, IN const PTR32 Rva, OUT PTR32* Va) {
    *Va = (PTR32)vm->pBaseAddr + Rva;
    return LOGICAL_TRUE;
}

/// <summary>
///	Converts file offset to virtual address </summary>
///
/// <param name="rpe">
/// Loaded VIRTUAL_MODULE32 struct </param>
/// <param name="Pa">
/// File offset </param>
/// <param name="Va">
/// Pointer that will recieve virtual address </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error </returns>
LOGICAL EXPORT LIBCALL MrPaToVa32(IN const VIRTUAL_MODULE32* vm, IN const PTR32 Pa, OUT PTR32* Va) {
    PTR32 Rva;

    if (!LOGICAL_SUCCESS(MrPaToRva32(&vm->PE, Pa, &Rva)))
        return LOGICAL_FALSE;
    return MrRvaToVa32(vm, Rva, Va);
}

/// <summary>
///	Calculates aligned virtual size </summary>
///
/// <param name="vpe">
/// Loaded RAW_PE32 </param>
/// <param name="Pa">
/// Pointer that will recieve file size </param>
///
/// <returns>
/// LOGICAL_TRUE always (no error checking) </returns>
LOGICAL EXPORT LIBCALL MrMaxPa32(IN const RAW_PE32* rpe, OUT PTR32* MaxPa) {
    PTR32 dwLargeAddr;
    unsigned int i;
    
    *MaxPa = rpe->pINH->OptionalHeader.SizeOfHeaders;
    if (!rpe->pINH->FileHeader.NumberOfSections)
        return LOGICAL_TRUE;
    for (i = 0; i < rpe->pINH->FileHeader.NumberOfSections; ++i) {
        dwLargeAddr = rpe->ppISH[i]->PointerToRawData + rpe->ppISH[i]->SizeOfRawData;
        *MaxPa = dwLargeAddr > *MaxPa ? dwLargeAddr : *MaxPa; // max(dwLargeAddr, *MaxPa) 
    }
    return LOGICAL_TRUE;
}

/// <summary>
///	Calculates aligned virtual size </summary>
///
/// <param name="vpe">
/// Loaded RAW_PE32 </param>
/// <param name="Rva">
/// Pointer that will recieve virtual size </param>
///
/// <returns>
/// LOGICAL_TRUE always (no error checking) </returns>
LOGICAL EXPORT LIBCALL MrMaxRva32(IN const RAW_PE32* rpe, OUT PTR32* MaxRva) {
    PTR32 dwLargeAddr;
    unsigned int i;
    
    *MaxRva = rpe->pINH->OptionalHeader.SizeOfHeaders;
    if (!rpe->pINH->FileHeader.NumberOfSections)
        return LOGICAL_TRUE;
    for (i = 0; i < rpe->pINH->FileHeader.NumberOfSections; ++i) {
        dwLargeAddr = rpe->ppISH[i]->VirtualAddress + MrAlignUp32(rpe->ppISH[i]->Misc.VirtualSize, rpe->pINH->OptionalHeader.SectionAlignment);
        *MaxRva = dwLargeAddr > *MaxRva ? dwLargeAddr : *MaxRva; // max(dwLargeAddr, *MaxRva) 
    }
    return LOGICAL_TRUE;
}

/// <summary>
///	Loads import list into rpe->pIL </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE32 </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE error, LOGICAL_MAYBE on crt/memory allocation error </returns>
LOGICAL EXPORT LIBCALL MrEnumerateImports32(INOUT RAW_PE32* rpe) {
    IMPORT_DESCRIPTOR   *iidDesc = NULL;
    THUNK_DATA32        *tdIat = NULL;
    IMPORT_NAME         *inName = NULL;
    IMPORT_LIBRARY32    *pIL = NULL;
    IMPORT_ITEM32       *pII = NULL;
    
    // do we even have to do imports?
    if (!rpe->pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size
     && !rpe->pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
        return LOGICAL_TRUE;
    rpe->pIL = (IMPORT_LIBRARY32*)calloc(1, sizeof(IMPORT_LIBRARY32));
    if (rpe->pIL == NULL)
        return LOGICAL_MAYBE;
    pIL = rpe->pIL;
    iidDesc = (IMPORT_DESCRIPTOR*)((PTR)rpe->pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (!LOGICAL_SUCCESS(MrGetRvaPtr32(rpe, (PTR32)iidDesc, (PTR*)&iidDesc)))
        return LOGICAL_FALSE;
    for (; iidDesc->Characteristics; ++iidDesc) {
        pIL->Library = (char*)iidDesc->Name;
        if (!LOGICAL_SUCCESS(MrGetRvaPtr32(rpe, (PTR32)pIL->Library, (PTR*)&pIL->Library)))
            return LOGICAL_FALSE;
        tdIat = (THUNK_DATA32*)iidDesc->FirstThunk;
        if (!LOGICAL_SUCCESS(MrGetRvaPtr32(rpe, (PTR32)tdIat, (PTR*)&tdIat)))
            return LOGICAL_FALSE;
        pII = (IMPORT_ITEM32*)calloc(1, sizeof(IMPORT_ITEM32));
        if (pII == NULL)
            return LOGICAL_MAYBE;
        pIL->iiImportList = pII;
        for (; tdIat->u1.Function; ++tdIat) {
            if (tdIat->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                pII->Ordinal = (char*)tdIat->u1.Ordinal;
            else {
                inName = (IMPORT_NAME*)tdIat->u1.AddressOfData;
                if (!LOGICAL_SUCCESS(MrGetRvaPtr32(rpe, (PTR32)inName, (PTR*)&inName)))
                    return LOGICAL_FALSE;
                pII->Name = (char*)inName->Name;
            }
            pII->dwItemPtr = (PTR32*)&tdIat->u1.AddressOfData;
            pII->Flink = calloc(1, sizeof(IMPORT_ITEM32));
            if (pII->Flink == NULL)
                return LOGICAL_MAYBE;
            pII = (IMPORT_ITEM32*)pII->Flink;
        }
        pIL->Flink = calloc(1, sizeof(IMPORT_LIBRARY32));
        if (pIL->Flink == NULL)
            return LOGICAL_MAYBE;
        pIL = (IMPORT_LIBRARY32*)pIL->Flink;
    }
    return LOGICAL_TRUE;
}

/// <summary>
///	Frees import lists in rpe->pIL </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE32 </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE error, LOGICAL_MAYBE on crt/memory allocation error </returns>
LOGICAL EXPORT LIBCALL MrFreeEnumeratedImports32(INOUT RAW_PE32* rpe) {
    IMPORT_LIBRARY32  *pIL = NULL,
                      *pILNext = NULL;
    IMPORT_ITEM32 *pII = NULL,
                  *pIINext = NULL;

    if (rpe->pIL == NULL)
        return LOGICAL_FALSE;
    
    for (pIL = rpe->pIL; pIL != NULL; pIL = pILNext) {
        for (pII = pIL->iiImportList; pII != NULL; pII = pIINext) {
            pIINext = (IMPORT_ITEM32*)pII->Flink;
            free(pII);
        }
        pILNext = (IMPORT_LIBRARY32*)pIL->Flink;
        free(pIL);
    }
    rpe->pIL = NULL;
    return LOGICAL_TRUE;
}

/// <summary>
///	Loads export list into rpe->pEL </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE32 </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE error, LOGICAL_MAYBE on crt/memory allocation error </returns>
LOGICAL EXPORT LIBCALL MrEnumerateExports32(INOUT RAW_PE32* rpe) {
    EXPORT_DIRECTORY* pED = NULL;
    EXPORT_LIST32* pEL = NULL;
    unsigned int i;

    PTR32* ppszNames = NULL;
    DWORD* ppdwOrdinals = NULL;
    PTR32* ppFunctionPtrs;

    // do we even have exports?
    if (!rpe->pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size
     && !rpe->pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
        return LOGICAL_TRUE;
    rpe->pEL = (EXPORT_LIST32*)calloc(1, sizeof(EXPORT_LIST32));
    if (rpe->pEL == NULL)
        return LOGICAL_MAYBE;
    pEL = rpe->pEL;
    pED = (EXPORT_DIRECTORY*)rpe->pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!LOGICAL_SUCCESS(MrGetRvaPtr32(rpe, (PTR32)pED, (PTR*)&pED)))
        return LOGICAL_FALSE;
    ppszNames = (PTR32*)pED->AddressOfNames;
    if (!LOGICAL_SUCCESS(MrGetRvaPtr32(rpe, (PTR32)ppszNames, (PTR*)&ppszNames)))
        return LOGICAL_FALSE;
    ppdwOrdinals = (DWORD*)pED->AddressOfNameOrdinals;
    if (!LOGICAL_SUCCESS(MrGetRvaPtr32(rpe, (PTR32)ppdwOrdinals, (PTR*)&ppdwOrdinals)))
        return LOGICAL_FALSE;
    ppFunctionPtrs = (PTR32*)pED->AddressOfFunctions;
    if (!LOGICAL_SUCCESS(MrGetRvaPtr32(rpe, (PTR32)ppFunctionPtrs, (PTR*)&ppFunctionPtrs)))
        return LOGICAL_FALSE;
    // wierd solution but theoretically one could be bigger so we'll pick the biggest one
    for (i = 0; i < (pED->NumberOfFunctions > pED->NumberOfNames ? pED->NumberOfFunctions : pED->NumberOfNames); ++i) {
        pEL->Name = (char*)*ppszNames++;
        MrGetRvaPtr32(rpe, (PTR32)pEL->Name, (PTR*)&pEL->Name);
        pEL->Ordinal = (char*)*ppdwOrdinals++;
        MrGetRvaPtr32(rpe, (PTR32)pEL->Ordinal, (PTR*)&pEL->Ordinal);
        pEL->dwItemPtr = (PTR32*)ppFunctionPtrs++;
        pEL->Flink = calloc(1, sizeof(EXPORT_LIST32));
        if (pEL->Flink == NULL)
            return LOGICAL_MAYBE;
        pEL = (EXPORT_LIST32*)pEL->Flink;
    }
    return LOGICAL_TRUE;
}

/// <summary>
///	Frees export list in rpe->pEL </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE32 </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE error, LOGICAL_MAYBE on crt/memory allocation error </returns>
LOGICAL EXPORT LIBCALL MrFreeEnumeratedExports32(INOUT RAW_PE32* rpe) {
    EXPORT_LIST32 *pEL = NULL,
                  *pELNext = NULL;

    if (rpe->pEL == NULL)
        return LOGICAL_FALSE;
    for (pEL = rpe->pEL; pEL != NULL; pEL = (EXPORT_LIST32*)pELNext) {
        pELNext = (EXPORT_LIST32*)pEL->Flink;
        free(pEL);
    }
    rpe->pEL = NULL;
    return LOGICAL_TRUE;
}

/// <summary>
///	Performs relocations on RAW_PE32 </summary>
///
/// <param name="rpe">
/// Loaded RAW_PE32 </param>
/// <param name="dwOldBase">
/// Current base address that rpe is relocated to, most likely rpe->pINH->OptionalHeader->ImageBase
/// <param name="dwNewBase">
/// Base to relocate to, most likely rpe->pIDH
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE error, LOGICAL_MAYBE on crt/memory allocation error </returns>
LOGICAL EXPORT LIBCALL MrRelocate32(INOUT RAW_PE32* rpe, IN const PTR32 dwOldBase, IN const PTR32 dwNewBase) {
    BASE_RELOCATION *brReloc = NULL;
    RELOC_ITEM *riItem = NULL;
    PTR32	 dwDelta;
    PTR      dwRelocAddr,
             dwRelocBase;
	DWORD	 cbRelocSection,
			 dwItems;

    // do we even have relocations?
	dwDelta = dwNewBase - dwOldBase;
	if (!dwDelta
	 || !rpe->pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
	 || !rpe->pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
		return LOGICAL_TRUE;

	cbRelocSection = rpe->pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	brReloc = (BASE_RELOCATION*)(rpe->pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    if(!LOGICAL_SUCCESS(MrGetRvaPtr32(rpe, (PTR32)brReloc, (PTR*)&brReloc)))
        return LOGICAL_FALSE;
	for (dwRelocBase = (PTR)brReloc; (PTR)brReloc < dwRelocBase + cbRelocSection; brReloc = (BASE_RELOCATION*)((PTR)brReloc + brReloc->SizeOfBlock)) {
		for (riItem = (RELOC_ITEM*)((PTR32)brReloc + sizeof(BASE_RELOCATION)), dwItems = brReloc->SizeOfBlock / sizeof(RELOC_ITEM); dwItems; --dwItems, ++riItem) {
			switch(riItem->Type) {
				case IMAGE_REL_BASED_HIGHLOW:
                    dwRelocAddr = brReloc->VirtualAddress + riItem->Offset;
                    if (!LOGICAL_SUCCESS(MrGetRvaPtr32(rpe, (PTR32)dwRelocAddr, &dwRelocAddr)))
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
	rpe->dwFlags.Relocated = TRUE;
	return LOGICAL_TRUE;
}