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
			if (Rva > rpe->ppISH[i]->VirtualAddress
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
LOGICAL EXPORT LIBCALL MrReadRva32(IN const RAW_PE32* rpe, IN const PTR32 Rva, IN void* pBuffer, IN const size_t cbBufferMax) {
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