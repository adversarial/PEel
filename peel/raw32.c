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
LOGICAL EXPORT LIBCALL MrGetRvaPtr32(INOUT const RAW_PE32* rpe, IN const PTR32 Rva, OUT PTR* Ptr) {
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
     || !rpe->pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
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

LOGICAL EXPORT LIBCALL MrEnumerateExports32(INOUT RAW_PE32* rpe) {
    EXPORT_DIRECTORY* pED = NULL;
    EXPORT_ITEM32* pEI = NULL;
    unsigned int i;

    PTR32* ppszNames = NULL;
    DWORD* ppdwOrdinals = NULL;
    PTR32* ppFunctionPtrs;

    // do we even have exports?
    if (!rpe->pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size
     || !rpe->pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
        return LOGICAL_TRUE;
    rpe->pEI = (EXPORT_ITEM32*)calloc(1, sizeof(EXPORT_ITEM32));
    if (rpe->pEI == NULL)
        return LOGICAL_MAYBE;
    pEI = rpe->pEI;
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
        pEI->Name = (char*)*ppszNames++;
        MrGetRvaPtr32(rpe, (PTR32)pEI->Name, (PTR*)&pEI->Name);
        pEI->Ordinal = (char*)*ppdwOrdinals++;
        MrGetRvaPtr32(rpe, (PTR32)pEI->Ordinal, (PTR*)&pEI->Ordinal);
        pEI->dwItemPtr = (PTR32*)ppFunctionPtrs++;
        pEI->Flink = calloc(1, sizeof(EXPORT_ITEM32));
        if (pEI->Flink == NULL)
            return LOGICAL_MAYBE;
        pEI = (EXPORT_ITEM32*)pEI->Flink;
    }
    return LOGICAL_TRUE;
}

LOGICAL EXPORT LIBCALL MrEnumerateRelocations32(INOUT RAW_PE32* rpe) {

}

//// needs fixing errywhere (error checks)
//// also add check for padding in between sections
//// rewrite with higher level implementation in HlpXxx!
//LOGICAL EXPORT LIBCALL MrDiscoverCaves32(INOUT RAW_PE32* rpe) {
//	CODECAVE_LIST32* pCave;
//	PTR32 dwMin;
//	unsigned int i,
//				 dwLowest;
//
//	memset(rpe->pCaveData, 0, sizeof(CODECAVE_LIST32));
//	pCave = rpe->pCaveData;
//	
//	// check for gap in headers
//	if (rpe->pINH->OptionalHeader.SizeOfHeaders > SIZEOF_PE_HEADERS32(rpe)) {
//		pCave->Size = rpe->pINH->OptionalHeader.SizeOfHeaders - SIZEOF_PE_HEADERS32(rpe);
//		pCave->VirtualSize = MrAlignUp32(rpe->pINH->OptionalHeader.SizeOfHeaders, rpe->pINH->OptionalHeader.SectionAlignment) - SIZEOF_PE_HEADERS32(rpe);
//		pCave->Rva = SIZEOF_PE_HEADERS32(rpe);
//		pCave->Offset = SIZEOF_PE_HEADERS32(rpe);
//		pCave->Attributes = PAGE_READONLY;
//		pCave->Flink = calloc(1, sizeof(CODECAVE_LIST32));
//		dmsg(TEXT("\nPotential codecave at RVA: 0x%08lx, size: 0x%08lx"), pCave->Rva, pCave->Size);
//		if (pCave == NULL)
//			return LOGICAL_MAYBE;
//		pCave = (CODECAVE_LIST32*)pCave->Flink;
//	}
//	// find lowest section in file
//	// find lowest section in memory
//	dwMin = MrAlignUp32(rpe->pINH->OptionalHeader.SizeOfHeaders, rpe->pINH->OptionalHeader.SectionAlignment);
//	// now check padding in sections
//	for (i = 0; i < rpe->pINH->FileHeader.NumberOfSections; ++i) {
//		if (rpe->ppISH[i]->Misc.VirtualSize < rpe->ppISH[i]->SizeOfRawData) {
//			pCave->Size = rpe->ppISH[i]->SizeOfRawData - rpe->ppISH[i]->Misc.VirtualSize;
//			pCave->VirtualSize = MrAlignUp32(rpe->ppISH[i]->Misc.VirtualSize, rpe->pINH->OptionalHeader.SectionAlignment) - rpe->ppISH[i]->Misc.VirtualSize;
//			pCave->Rva = rpe->ppISH[i]->VirtualAddress + rpe->ppISH[i]->Misc.VirtualSize;
//			pCave->Offset = rpe->ppISH[i]->PointerToRawData + rpe->ppISH[i]->Misc.VirtualSize;
//			pCave->Attributes = rpe->ppISH[i]->Characteristics;
//			pCave->Flink = calloc(1, sizeof(CODECAVE_LIST32));
//			dmsg(TEXT("\nPotential codecave at RVA: 0x%08lx, size: 0x%08lx"), pCave->Rva, pCave->Size);
//			if (pCave == NULL)
//				return LOGICAL_MAYBE;
//			pCave = (CODECAVE_LIST32*)pCave->Flink;
//		}
//	}
//}
//
//LOGICAL EXPORT LIBCALL MrFreeCaves32(INOUT RAW_PE32* rpe) {
//	CODECAVE_LIST32 *pCave = NULL,
//					*pNext = NULL;
//
//	for (pCave = (CODECAVE_LIST32*)rpe->pCaveData; pCave != NULL; pCave = pNext) {
//		pNext = (CODECAVE_LIST32*)pCave->Flink; 
//		free(pCave);
//	}
//	return LOGICAL_TRUE;
//}