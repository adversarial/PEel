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
   released under LGPL3.0 (see LICENSE in distribution folder). It can handle both file
   and mapped alignments, and provides raw access to the entire PE file.
   xml-style documentation for each function is found in xxx_public.h above each function
   by x8esix
*/

/* Addendum: 

NOTICE : THIS LIBRARY IS NOT "COMPLETE" UNTIL v1.0

X = done
* = partially done/in progress

    What we care about:
    [ ] x64 support ( lol )
    [X]	Loading a PE file
    [X] Imports/Exports ( simply needs to be integrated into new RAW_PE format... todo )
    [ ] Resources ( 0xffffffffffffffffUL)
    [X] Relocations ( simply needs to be integrated into new RAW_PE format... todo )
    [ ] TLS ( lack of documentation requires RE )
    [X] Add logging for debugging... ( why wasn't this done before? bp are annoying ) [ 8/2/13 ]

    What we don't care about:
        Things outside our control
            NX ( we probably should compImporte without it... or just manually change the flag )
        Making this into a packer
            That's a seperate project ;)

    TODO:
    [*] Update public header
    [X] Fix crashes on files with 0 sections
    [ ] Safety dance!
    [*] Documentation! ( is a bitch )

Additional notes:
    Function namespace styling:
        PlXxx  - 
            low level functions that control individual aspects or generally useful snips
        HlpXxx -
            high level functions to abstract loading
*/

#pragma region Structs
#	pragma pack(push, 1)

        typedef struct _DOS_HEADER_STUB {
            BYTE Stub[0x0e];	// 16bit stub
            char dsMsg[0x2a];	// variable size, 2a is default msvc, '$' terminated
        } DOS_STUB;
        
        typedef struct _PE_LOADING_FLAGS { // ptr size for alignment, can be adjusted if necessary
            PTR     Relocated : 1,	// relocations are resolved
                    Imported  : 1,	// imports are resolved
                    Protected : 1,	// image has proper protection
                    Attached  : 1;	// points to an externally allocated image
        } PE_FLAGS;

        typedef struct _CODECAVE_LINKED_LIST32 {
            PTR32	Offset,		// physical offset
                    Rva,		// 
                    Size,		// cb of file cave (can be 0)
                    VirtualSize;// cb of image cave (can be 0)
            DWORD	Attributes;	// Page protection
            void   *Data,
                   *Flink;
        } CODECAVE_LIST32;	// stores data that was in padding/outside of sections

        typedef struct _CODECAVE_LINKED_LIST64 {
            PTR64	Offset,		// physical offset
                    Rva,		// none of these fields need to be PTR64 but okay
                    Size,		// cb of file cave (can be 0)
                    VirtualSize;// cb of image cave (can be 0)
            DWORD	Attributes;	// Page protection
            void   *Data,
                   *Flink;
        } CODECAVE_LIST64;	// stores data that was in padding/outside of sections

        typedef struct _IMPORT_ITEM_FLIST32 {
            char  *Name,          // ptr to function name (NULL if by ordinal)
                  *Ordinal;       // ptr to DWORD ordinal number (NULL if by name)
            PTR32 *dwItemPtr;     // ptr to IAT entry
            void  *Flink;
        } IMPORT_ITEM32;       // forward linked list of imports

        typedef struct _IMPORT_ITEM_FLIST64 {
            char  *Name,          // ptr to function name (NULL if by ordinal)
                  *Ordinal;       // ptr to DWORD ordinal number (NULL if by name)
            PTR64 *dwItemPtr;     // ptr to IAT entry
            void  *Flink;
        } IMPORT_ITEM64;

        typedef struct _IMPORT_LIBRARY_FLIST32 {
            char          *Library; // ptr to char* that hold library name
            IMPORT_ITEM32 *iiImportList;
            void          *Flink;
        } IMPORT_LIBRARY32;

        typedef struct _IMPORT_LIBRARY_FLIST64 {
            char          *Library; // ptr to char* that hold library name
            IMPORT_ITEM64 *iiImportList;
            void          *Flink;
        } IMPORT_LIBRARY64;

        typedef struct _EXPORT_ITEM_FLIST32 {
            char  *Name,
                  *Ordinal;
            PTR32 *dwItemPtr;
            void  *Flink;
        } EXPORT_LIST32;

        typedef struct _EXPORT_ITEM_FLIST64 {
            char  *Name,
                  *Ordinal;
            PTR64 *dwItemPtr;
            void  *Flink;
        } EXPORT_LIST64;

        typedef struct _RESOURCE_ITEM_FLIST32 {
            PTR    dwType;
            char  *Name;
            PTR    wId; // only use lower WORD
            size_t cbSize;
            void  *pData,
                  *Flink;
        } RESOURCE_LIST32;

        typedef struct _RESOURCE_ITEM_FLIST64 {
            char  *Name;
            PTR    wId; // only use lower WORD
            void  *pData,
                  *Flink;
        } RESOURCE_LIST64;

        typedef struct _RAW_PE32 {
            DOS_HEADER		 *pDosHdr;
            DOS_STUB 		 *pDosStub;
            NT_HEADERS32 	 *pNtHdr;
            SECTION_HEADER  **ppSecHdr;		    // array pointing to section headers
            void		    **ppSectionData;    // array pointing to section data
            PE_FLAGS		  LoadStatus;
// essentials (pointers only)
// the following allocate memory and, however are only used when their respective functions are called
            CODECAVE_LIST32  *pCaveData;	    // forward-linked list containing codecaves
            IMPORT_LIBRARY32 *pImport;              // forward-linked list of imports
            EXPORT_LIST32    *pExport;              // forward-linked list of exports
            RESOURCE_LIST32  *pResource;              // forward-linked list of resources
        } RAW_PE32;	// wraps PE file

        typedef struct _RAW_PE64 {
            DOS_HEADER		 *pDosHdr;
            DOS_STUB 		 *pDosStub;
            NT_HEADERS64 	 *pNtHdr;
            SECTION_HEADER  **ppSecHdr;		    // array pointing to section headers
            void		    **ppSectionData;    // array pointing to section data
            PE_FLAGS		  LoadStatus;
// essentials (pointers only)
// the following allocate memory and, however are only used when their respective functions are called
            CODECAVE_LIST64  *pCaveData;	    // forward-linked list containing codecaves
            IMPORT_LIBRARY64 *pImport;              // forward-linked list of imports
            EXPORT_LIST64    *pExport;              // forward-linked list of exports
            RESOURCE_LIST64  *pRI;              // forward-linked list of resources
        } RAW_PE64;	// contains PE file

        typedef struct _VIRTUAL_PE_MODULE32 {
            RAW_PE32    PE;
            void	   *Flink,
                       *Blink;
            char		cName[8];	// identification of loaded DLLS, not sz
            void*		pBaseAddr;	// if headers aren't loaded
        } VIRTUAL_MODULE32;	// wrapper to represent aligned PE

        typedef struct _VIRTUAL_PE_MODULE64 {
            RAW_PE64    PE;
            void	   *Flink,
                       *Blink;
            char		cName[8];	// identification of loaded DLLS, not sz
            void*		pBaseAddr;	// if headers aren't loaded
        } VIRTUAL_MODULE64;	// wrapper to represent aligned PE

        typedef struct {
           uint16_t Offset	: 12,
                    Type	: 4;
        } RELOC_ITEM;
#	pragma pack(pop)
#pragma endregion

#pragma region Debugging
#	ifdef DEBUGMODE
#		include <stdio.h>
#		include <tchar.h>
#		define dmsg	PlDebugOut
        LOGICAL CDECL PlDebugOut(IN const TCHAR* tzFormat, ...);
#	else
#		define dmsg(msg, ...)
#	endif
#pragma endregion

#pragma region Basic Mode Prototypes
    // alignment & such
    PTR32 EXPORT LIBCALL PlAlignUp32(IN const PTR32 offset, IN const PTR32 alignment);
    PTR32 EXPORT LIBCALL PlAlignDown32(IN const PTR32 offset, IN const PTR32 alignment);
    
    PTR64 EXPORT LIBCALL PlAlignUp64(IN const PTR64 offset, IN const PTR64 alignment);
    PTR64 EXPORT LIBCALL PlAlignDown64(IN const PTR64 offset, IN const PTR64 alignment);
    // conversions
    DWORD EXPORT LIBCALL PlSectionToPageProtection(IN const DWORD dwCharacteristics);
    DWORD EXPORT LIBCALL PlPageToSectionProtection(IN const DWORD dwProtection);
#pragma endregion

#pragma region Macros
#	define SIZEOF_PE_HEADERS32(rpe) (rpe->pDosHdr->e_lfanew + \
                                     sizeof(NT_HEADERS32) + \
                                     sizeof(SECTION_HEADER) * rpe->pNtHdr->FileHeader.NumberOfSections)
#   define SIZEOF_PE_HEADERS64(rpe) (rpe->pDosHdr->e_lfanew + \
                                     sizeof(NT_HEADERS64) + \
                                     sizeof(SECTION_HEADER) * rpe->pNtHdr->FileHeader.NumberOfSections)
#pragma endregion

#include "raw32.h"
#include "file32.h"
#include "virtual32.h"