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

#pragma once

#include "preproc.h"
#include "types.h"

/* 
   PEel: PE editing library
  
   PEel is an opensource, lowlevel library for gathering information and modifying PE files
   released under LGPL3.0 (see LICENSE in distribution folder)
   xml-style documentation for each function is found in xxx_public.h above each function
   by x8esix
*/

/* Addendum: 

NOTICE : THIS LIBRARY IS NOT "COMPLETE" UNTIL v1.0

X = done
* = partially done/in progress

    What we care about:
    [X]	Loading a PE file
    [*] Imports/Exports ( simply needs to be integrated into new RAW_PE format... todo )
    [*] Relocations ( simply needs to be integrated into new RAW_PE format... todo )
    [X] Add logging for debugging... ( why wasn't this done before? bp are annoying ) [ 8/2/13 ]

    What we don't care about:
        Things outside our control
            NX ( we probably should compile without it... or just manually change the flag )
        Making this into a packer
            That's a seperate project ;)

    TODO:
    [ ] Update public header
    [ ] Fix crashes on files with 0 sections
    [ ] Safety dance!
    [ ] Documentation! ( is a bitch )

Additional notes:
    Function namespace styling:
        MrXxx  - 
            low level functions that control individual aspects or generally useful snips
        HlpXxx -
            high level functions to abstract loading
        mrXxx  -
            alternative c library (libctiny is currently being used, however)
*/

#pragma region Structs
#	pragma pack(push, 1)

        typedef struct {
            BYTE Stub[0x0e];	// 16bit stub
            char dsMsg[0x2a];	// variable size, 2a is default msvc, '$' terminated
        } DOS_STUB;
        
        typedef struct {
            uint32_t Relocated : 1,	// relocations are resolved
                    Imported  : 1,	// imports are resolved
                    Protected : 1,	// image has proper protection
                    Attached  : 1;	// points to an externally allocated image
        } PE_FLAGS;

        typedef struct {
            PTR32	Offset,		// physical offset
                    Rva,		// 
                    Size,		// cb of file cave (can be 0)
                    VirtualSize;// cb of image cave (can be 0)
            DWORD	Attributes;	// Page protection
            void   *Data,
                   *Flink;
        } CODECAVE_LIST32;	// stores data that was in padding/outside of sections

        typedef struct {
            DOS_HEADER		*pIDH;
            DOS_STUB		*pIDS;
            NT_HEADERS32	*pINH;
            SECTION_HEADER **ppISH;			// array pointing to section headers
            void		   **ppSectionData;	// array pointing to section data
            CODECAVE_LIST32 *pCaveData;		// forward-linked list containing codecaves
            PE_FLAGS		 dwFlags;
        } RAW_PE32;	// contains PE file

        typedef struct {
            RAW_PE32	PE;
            void	   *Flink,
                       *Blink;
            char		cName[8];	// identification of loaded DLLS, not sz
            void*		pBaseAddr;	// if headers aren't loaded
        } VIRTUAL_MODULE32;	// wrapper to represent aligned PE

        typedef struct {
           uint16_t Offset	: 12,
                    Type	: 4;
        } RELOC_ITEM;
#		pragma pack(pop)
#pragma endregion

#pragma region Debugging
#	ifdef DEBUGMODE
#		include <stdio.h>
#		include <tchar.h>
#		define dmsg	MrDebugOut
        LOGICAL CDECL MrDebugOut(IN const TCHAR* tzFormat, ...);
#	else
#		define dmsg(msg, ...)
#	endif
#pragma endregion

#pragma region Basic Mode Prototypes
    // alignment & such
    PTR32 EXPORT LIBCALL MrAlignUp32(IN const PTR32 offset, IN const PTR32 alignment);
    PTR32 EXPORT LIBCALL MrAlignDown32(IN const PTR32 offset, IN const PTR32 alignment);
    
    DWORD EXPORT LIBCALL MrSectionToPageProtection32(IN const DWORD dwCharacteristics);
    DWORD EXPORT LIBCALL MrPageToSectionProtection32(IN DWORD dwProtection);
#pragma endregion

#pragma region Macros
#	define SIZEOF_PE_HEADERS32(rpe) (rpe->pIDH->e_lfanew + \
                                     sizeof(NT_HEADERS32) + \
                                     sizeof(SECTION_HEADER) * rpe->pINH->FileHeader.NumberOfSections)
#pragma endregion

#include "raw32.h"
#include "file32.h"
#include "virtual32.h"