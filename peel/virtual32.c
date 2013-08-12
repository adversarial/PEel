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

#include "virtual32.h"

/// <summary>
///	Fills VIRTUAL_MODULE32 with loaded image's information </summary>
///
/// <param name="pModuleBase">
/// Base address of target image </param>
/// <param name="vm">
/// Pointer to VIRTUAL_MODULE32 struct to recieve information about target </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT error </returns>
LOGICAL EXPORT LIBCALL MrAttachImage32(IN const void* const pModuleBase, OUT VIRTUAL_MODULE32* vm) {
	unsigned int i;
	
	// leave other members alone (name needs to be set externally)
	memset(&vm->PE, 0, sizeof(RAW_PE32));

	vm->pBaseAddr = (void*)pModuleBase;
	vm->PE.pIDH = (DOS_HEADER*)pModuleBase;
#if ! ACCEPT_INVALID_SIGNATURES
	if (vm->PE.pIDH->e_magic != IMAGE_DOS_SIGNATURE)
		return LOGICAL_FALSE;
#endif
	vm->PE.pIDS = (DOS_STUB*)((PTR)vm->pBaseAddr + sizeof(DOS_HEADER));
	vm->PE.pINH = (NT_HEADERS32*)((PTR)vm->pBaseAddr + vm->PE.pIDH->e_lfanew);
#if ! ACCEPT_INVALID_SIGNATURES
	if (vm->PE.pINH->Signature != IMAGE_NT_SIGNATURE
	 || vm->PE.pINH->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		dmsg(TEXT("\nNT Headers signature or magic invalid!"));
		return LOGICAL_FALSE;
	}
#endif
	if (vm->PE.pINH->FileHeader.NumberOfSections) {
		vm->PE.ppISH = (SECTION_HEADER**)malloc(vm->PE.pINH->FileHeader.NumberOfSections * sizeof(SECTION_HEADER*));
		if (vm->PE.ppISH == NULL)
			return LOGICAL_MAYBE;
		vm->PE.ppSectionData = (void**)malloc(vm->PE.pINH->FileHeader.NumberOfSections * sizeof(void*));
		if (vm->PE.ppSectionData == NULL)
			return LOGICAL_MAYBE;
		for (i = 0; i < vm->PE.pINH->FileHeader.NumberOfSections; ++i) {
			vm->PE.ppISH[i] = (SECTION_HEADER*)((PTR)&vm->PE.pINH->OptionalHeader + vm->PE.pINH->FileHeader.SizeOfOptionalHeader + (sizeof(SECTION_HEADER) * i));
			vm->PE.ppSectionData[i] = (void*)((PTR)vm->pBaseAddr + vm->PE.ppISH[i]->VirtualAddress);
		}
	} else {
		vm->PE.ppISH = NULL;
		vm->PE.ppSectionData = NULL;
		dmsg(TEXT("\nPE image at 0x%p has 0 sections!"), vm->pBaseAddr);
	}
	memset(&vm->PE.dwFlags, 0, sizeof(vm->PE.dwFlags));
	vm->PE.dwFlags.Attached = TRUE;
	dmsg(TEXT("\nAttached to PE image at 0x%p"), vm->pBaseAddr);
	return LOGICAL_TRUE;
}

/// <summary>
///	Releases memory allocated by XxAttachImage32 </summary>
///
/// <param name="vm">
/// Pointer to loaded VIRTUAL_MODULE32 struct </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT error </returns>
LOGICAL EXPORT LIBCALL MrDetachImage32(INOUT VIRTUAL_MODULE32* vm) {
	if (!vm->PE.dwFlags.Attached)
		return LOGICAL_FALSE;

	if (vm->PE.ppISH != NULL)
		free(vm->PE.ppISH);
	if (vm->PE.ppSectionData != NULL)
		free(vm->PE.ppSectionData);
	dmsg(TEXT("\nDetached from PE image at 0x%p"), vm->pBaseAddr);
	memset(&vm->PE, 0, sizeof(RAW_PE32));
	return LOGICAL_TRUE;
}

/// <summary>
///	Converts image to file alignment </summary>
///
/// <param name="vpe">
/// Pointer to VIRTUAL_MODULE32 containing loaded image </param>
/// <param name="rpe">
/// Pointer to RAW_PE32 struct </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT/memory error </returns>
LOGICAL EXPORT LIBCALL MrImageToFile32(IN const VIRTUAL_MODULE32* vm, OUT RAW_PE32* rpe) {
	PTR32 MaxPa;
	void* pImage = NULL;

	if (!LOGICAL_SUCCESS(MrMaxPa32(&vm->PE, &MaxPa)))
		return LOGICAL_FALSE;
	pImage = VirtualAlloc(NULL, MaxPa, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pImage == NULL)
		return LOGICAL_MAYBE;
	return MrImageToFile32Ex(vm, (PTR)pImage, rpe);
}

/// <summary>
///	Converts image to file alignment </summary>
///
/// <param name="vpe">
/// Pointer to VIRTUAL_MODULE32 containing loaded image </param>
/// <param name="pImageBuffer">
/// Buffer of at least MrMaxPa32(&vm->Pe,) size with at least PAGE_READWRITE attributes
/// <param name="rpe">
/// Pointer to RAW_PE32 struct </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT/memory error </returns>
LOGICAL EXPORT LIBCALL MrImageToFile32Ex(IN const VIRTUAL_MODULE32* vm, IN const PTR pImageBuffer, OUT RAW_PE32* rpe) {
	PTR32 MaxPa;
	unsigned int i;
	
	// unnecessary per standard, but let's play nice with gaps
	if (!LOGICAL_SUCCESS(MrMaxPa32(&vm->PE, &MaxPa)))
		return LOGICAL_FALSE;
	memset((void*)pImageBuffer, 0, MaxPa);
	
	rpe->pIDH = (DOS_HEADER*)pImageBuffer;
	memcpy(rpe->pIDH, vm->PE.pIDH, sizeof(DOS_HEADER));
	rpe->pIDS = (DOS_STUB*)((PTR)rpe->pIDH + sizeof(DOS_HEADER));
	memcpy(rpe->pIDS, vm->PE.pIDS, rpe->pIDH->e_lfanew - sizeof(DOS_HEADER));
	rpe->pINH = (NT_HEADERS32*)((PTR)rpe->pIDH + rpe->pIDH->e_lfanew);
	memcpy(rpe->pINH, vm->PE.pINH, sizeof(NT_HEADERS32));
	if (rpe->pINH->FileHeader.NumberOfSections) {
		rpe->ppISH = (SECTION_HEADER**)malloc(rpe->pINH->FileHeader.NumberOfSections * sizeof(SECTION_HEADER*));
		if (rpe->ppISH == NULL)
			return LOGICAL_MAYBE;
		rpe->ppSectionData = (void**)malloc(rpe->pINH->FileHeader.NumberOfSections * sizeof(void*));
		if (rpe->ppSectionData == NULL)
			return LOGICAL_MAYBE;
		for (i = 0; i < rpe->pINH->FileHeader.NumberOfSections; ++i) {
			rpe->ppISH[i] = (SECTION_HEADER*)((PTR)&rpe->pINH->OptionalHeader + rpe->pINH->FileHeader.SizeOfOptionalHeader + sizeof(SECTION_HEADER) * i);
			memcpy(rpe->ppISH[i], vm->PE.ppISH[i], sizeof(SECTION_HEADER));
			rpe->ppSectionData[i] = (void*)((PTR)rpe->pIDH + rpe->ppISH[i]->PointerToRawData);
			memcpy(rpe->ppSectionData[i], vm->PE.ppSectionData[i], rpe->ppISH[i]->SizeOfRawData);
		}
	} else {
		rpe->ppISH = NULL;
		rpe->ppSectionData = NULL;
	}
	memset(&rpe->dwFlags, 0, sizeof(rpe->dwFlags));
	rpe->dwFlags = vm->PE.dwFlags;
	rpe->dwFlags.Attached = FALSE;
	return LOGICAL_TRUE;
}

/// <summary>
///	Frees a mapped image that was allocated </summary>
///
/// <param name="vm">
/// Loaded VIRTUAL_MODULE32 struct that is not attached </param>
///
/// <returns>
/// LOGICAL_TRUE on success, LOGICAL_FALSE on PE related error, LOGICAL_MAYBE on CRT/memory error, *vm is zeroed </returns>
LOGICAL EXPORT LIBCALL MrFreeImage32(INOUT VIRTUAL_MODULE32* vm) {
	VIRTUAL_MODULE32 *vmNext,
					 *vmPrev;
	
	if (vm->PE.dwFlags.Attached == TRUE)
		return LOGICAL_FALSE;

	if (vm->PE.ppISH != NULL)
		free(vm->PE.ppISH);
	if (vm->PE.ppSectionData != NULL)
		free(vm->PE.ppSectionData);
	VirtualFree(vm->pBaseAddr, 0, MEM_RELEASE);

	dmsg(TEXT("\nUnlinking PE Image at %p"), vm->pBaseAddr);
	vmPrev = (VIRTUAL_MODULE32*)vm->Blink;
	vmNext = (VIRTUAL_MODULE32*)vm->Flink;
	if (vmPrev != NULL)
		vmPrev->Flink = vmNext;
	if (vmNext != NULL)
		vmNext->Blink = vmPrev;
	memset(vm, 0, sizeof(VIRTUAL_MODULE32));
	return LOGICAL_TRUE;
}