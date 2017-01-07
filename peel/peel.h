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
    [*] x64 support ( lol )
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
            char dsMsg[0x2a];   // variable size, 2a is default msvc, '$' terminated
        } DOS_STUB;
        
        typedef struct _PE_LOADING_FLAGS { // ptr size for alignment, can be adjusted if necessary
            PTR     Relocated : 1,  // relocations are resolved
                    Imported  : 1,  // imports are resolved
                    Protected : 1,  // image has proper protection
                    Attached  : 1;  // points to an externally allocated image
        } PE_FLAGS;

        typedef struct _CODECAVE_LINKED_LIST32 {
            PTR	    Offset,		// physical offset
                    Rva,        // virtual address
                    Size,       // cb of file cave (can be 0)
                    VirtualSize;// cb of image cave (can be 0)
            DWORD	Attributes;   // Page protection
            void   *Data,
                   *Flink;
        } CODECAVE_LIST;	// stores data that was in padding/outside of sections

        typedef struct _IMPORT_ITEM_FLIST {
            char  *Name,          // ptr to function name (NULL if by ordinal)
                  *Ordinal;       // ptr to DWORD ordinal number (NULL if by name)
            PTR32 *dwItemPtr;     // ptr to IAT entry
            void  *Flink;
        } IMPORT_ITEM;       // forward linked list of imports

        typedef struct _IMPORT_LIBRARY_FLIST {
            char          *Library; // ptr to char* that hold library name
            IMPORT_ITEM   *iiImportList;
            void          *Flink;
        } IMPORT_LIBRARY;

        typedef struct _EXPORT_ITEM_FLIST {
            char  *Name,
                  *Ordinal;
            PTR32 *dwItemPtr;
            void  *Flink;
        } EXPORT_LIST;

        typedef struct _RESOURCE_ITEM_FLIST {
            PTR    dwType;
            char  *Name;
            PTR    wId; // only use lower WORD
            size_t cbSize;
            void  *pData,
                  *Flink;
        } RESOURCE_LIST;
        
        typedef struct _RAW_PE {
            DOS_HEADER		  *pDosHdr;
            DOS_STUB 		  *pDosStub;
#if SUPPORT_PE32PLUS
            NT_HEADERS64      *pNtHdr;
#else
            NT_HEADERS32      *pNtHdr;
#endif
            SECTION_HEADER   **ppSecHdr;		    // array pointing to section headers
            void		     **ppSectionData;       // array pointing to section data
            PE_FLAGS		   LoadStatus;
// essentials (pointers only)
// the following allocate memory and, however are only used when their respective functions are called
            CODECAVE_LIST     *pCaveData;	    // forward-linked list containing codecaves
            IMPORT_LIBRARY    *pImport;              // forward-linked list of imports
            EXPORT_LIST       *pExport;              // forward-linked list of exports
            RESOURCE_LIST     *pResource;              // forward-linked list of resources
        } RAW_PE;	// wraps PE file


        typedef struct _VIRTUAL_PE_MODULE32 {
            RAW_PE      PE;
            void	   *Flink,
                       *Blink;
            char		cName[8];	// identification of loaded DLLS, not sz
            void*		pBaseAddr;	// if headers aren't loaded
        } VIRTUAL_MODULE;	// wrapper to represent aligned PE
        
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
    PTR32 EXPORT LIBCALL PlAlignUp(IN const PTR offset, IN const PTR alignment);
    PTR32 EXPORT LIBCALL PlAlignDown(IN const PTR offset, IN const PTR alignment);
    // conversions
    DWORD EXPORT LIBCALL PlSectionToPageProtection(IN const DWORD dwCharacteristics);
    DWORD EXPORT LIBCALL PlPageToSectionProtection(IN const DWORD dwProtection);
#pragma endregion

#include "raw.h"
#include "file.h"
#include "virtual.h"
