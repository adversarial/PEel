// for dynamic linking to PEel32Plus.dll

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

// this header last updated on 10.27.2013

#pragma once

#include <Windows.h>    // will get rid of this eventually
#include <stdint.h>

#pragma region Preprocessor
#	define LIBCALL  __stdcall
#   define IN
#   define OUT
#   define INOUT
#pragma endregion

#pragma region Types
#   pragma region Basic Types
        typedef uint32_t PTR32;
        typedef uint64_t PTR64;

        typedef PTR64 PTR;

        typedef signed char LOGICAL;

#   	define LOGICAL_SUCCESS(x) (!x)
#   	define LOGICAL_FAILURE(x) (x > 0)
#   	define LOGICAL_THIRD(x) (x < 0)

#   	define LOGICAL_TRUE		(LOGICAL)0	// on success
#   	define LOGICAL_FALSE	(LOGICAL)1	// on failure
#   	define LOGICAL_MAYBE	(LOGICAL)-1	// on 3rd-party failure
#   pragma endregion

#pragma region Windows Proxies
    #pragma region Types Defines
        typedef IMAGE_DOS_HEADER		 DOS_HEADER;
        typedef IMAGE_FILE_HEADER        FILE_HEADER;
        typedef IMAGE_OPTIONAL_HEADER32  OPTIONAL_HEADER32;
        typedef IMAGE_OPTIONAL_HEADER64  OPTIONAL_HEADER64;
        typedef IMAGE_NT_HEADERS32       NT_HEADERS32;
        typedef IMAGE_NT_HEADERS64		 NT_HEADERS64;
        typedef NT_HEADERS64             NT_HEADERS;
        typedef IMAGE_SECTION_HEADER	 SECTION_HEADER;
        typedef IMAGE_BASE_RELOCATION	 BASE_RELOCATION;
        typedef IMAGE_IMPORT_DESCRIPTOR  IMPORT_DESCRIPTOR;
        typedef IMAGE_THUNK_DATA32		 THUNK_DATA32;
        typedef IMAGE_THUNK_DATA64       THUNK_DATA64;
        typedef THUNK_DATA64             THUNK_DATA;
        typedef IMAGE_IMPORT_BY_NAME	 IMPORT_NAME;
        typedef IMAGE_EXPORT_DIRECTORY   EXPORT_DIRECTORY;
        typedef IMAGE_DEBUG_DIRECTORY    DEBUG_DIRECTORY;
        typedef IMAGE_RESOURCE_DIRECTORY RESOURCE_DIRECTORY;
        typedef IMAGE_RESOURCE_DIRECTORY_ENTRY RESOURCE_DIRECTORY_ENTRY;
        typedef IMAGE_RESOURCE_DATA_ENTRY RESOURCE_DATA_ENTRY;
        
        #define OPT_HDR_MAGIC32 IMAGE_NT_OPTIONAL_HDR32_MAGIC
        #define OPT_HDR_MAGIC64 IMAGE_NT_OPTIONAL_HDR64_MAGIC
        #define OPT_HDR_MAGIC OPT_HDR_MAGIC64
    #pragma endregion
#pragma endregion
#pragma endregion

#pragma region Structs
#	pragma pack(push, 1)

        typedef struct _DOS_HEADER_STUB {
            BYTE Stub[0x0e];	// 16bit stub
            char dsMsg[0x2a];	// variable size, 2a is default msvc, '$' terminated
        } DOS_STUB;
        
        typedef struct _PE_LOADING_FLAGS { // ptr size for alignment, can be adjusted if necessary
            PTR32   Relocated : 1,	// relocations are resolved
                    Imported  : 1,	// imports are resolved
                    Protected : 1,	// image has proper protection
                    Attached  : 1;	// points to an externally allocated image
        } PE_FLAGS;

        typedef struct _CODECAVE_LINKED_LIST32 {
            PTR	    Offset,		// physical offset
                    Rva,		// 
                    Size,		// cb of file cave (can be 0)
                    VirtualSize;// cb of image cave (can be 0)
            DWORD	Attributes;	// Page protection
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
        
        typedef struct _RAW_PE64 {
            DOS_HEADER		  *pDosHdr;
            DOS_STUB 		  *pDosStub;
            NT_HEADERS64      *pNtHdr;
            SECTION_HEADER   **ppSecHdr;		    // array pointing to section headers
            void		     **ppSectionData;       // array pointing to section data
            PE_FLAGS		   LoadStatus;
// essentials (pointers only)
// the following allocate memory and, however are only used when their respective functions are called
            CODECAVE_LIST     *pCaveData;	    // forward-linked list containing codecaves
            IMPORT_LIBRARY    *pImport;              // forward-linked list of imports
            EXPORT_LIST       *pExport;              // forward-linked list of exports
            RESOURCE_LIST     *pResource;              // forward-linked list of resources
        } RAW_PE64;	// wraps PE file


        typedef struct _VIRTUAL_PE_MODULE32 {
            RAW_PE64      PE;
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

#pragma region Prototypes
#   pragma region Peel
        PTR64 LIBCALL PlAlignUp64(IN const PTR64 offset, IN const PTR64 alignment);
        PTR64 LIBCALL PlAlignDown64(IN const PTR64 offset, IN const PTR64 alignment);

        DWORD LIBCALL PlSectionToPageProtection(IN const DWORD dwCharacteristics);
        DWORD LIBCALL PlPageToSectionProtection(IN const DWORD dwProtection);
#   pragma endregion
#   pragma region Raw
// these can operate on any filled RAW_PE64 regardless of alignment
        LOGICAL LIBCALL PlRvaToPa64(IN const RAW_PE64* rpe, IN const PTR Rva, OUT PTR* Pa);
        LOGICAL LIBCALL PlPaToRva64(IN const RAW_PE64* rpe, IN const PTR Pa, OUT PTR* Rva);

        LOGICAL LIBCALL PlGetRvaPtr64(IN const RAW_PE64* rpe, IN const PTR Rva, OUT PTR* Ptr);
        LOGICAL LIBCALL PlGetPaPtr64(IN const RAW_PE64* rpe, IN const PTR Pa, OUT PTR* Ptr);

        LOGICAL LIBCALL PlWriteRva64(INOUT RAW_PE64* rpe, IN const PTR Rva, IN const void* pData, IN size_t cbData);
        LOGICAL LIBCALL PlReadRva64(IN const RAW_PE64* rpe, IN const PTR Rva, IN void* pBuffer, IN size_t cbBufferMax);
        LOGICAL LIBCALL PlWritePa64(INOUT RAW_PE64* rpe, IN const PTR Pa, IN const void* pData, IN size_t cbData);
        LOGICAL LIBCALL PlReadPa64(IN const RAW_PE64* rpe, IN const PTR Pa, IN void* pBuffer, IN size_t cbBufferMax);

        LOGICAL LIBCALL PlRvaToVa64(IN const VIRTUAL_MODULE64* vm, IN const PTR Rva, OUT PTR* Va);
        LOGICAL LIBCALL PlPaToVa64(IN const VIRTUAL_MODULE64* vm, IN const PTR Pa, OUT PTR* Va);

        LOGICAL LIBCALL PlMaxPa64(IN const RAW_PE64* rpe, OUT PTR* MaxPa);
        LOGICAL LIBCALL PlMaxRva64(IN const RAW_PE64* rpe, OUT PTR* MaxRva);
    
        LOGICAL LIBCALL PlEnumerateImports64(INOUT RAW_PE64* rpe);
        LOGICAL LIBCALL PlFreeEnumeratedImports64(INOUT RAW_PE64* rpe);

        LOGICAL LIBCALL PlEnumerateExports64(INOUT RAW_PE64* rpe);
        LOGICAL LIBCALL PlFreeEnumeratedExports64(INOUT RAW_PE64* rpe);

        LOGICAL LIBCALL PlRelocate64(INOUT RAW_PE64* rpe, IN const PTR dwOldBase, IN const PTR dwNewBase);
    
        LOGICAL LIBCALL PlCalculateChecksum64(INOUT RAW_PE64* rpe, OUT DWORD* dwChecksum);

        LOGICAL LIBCALL PlSizeofPeHeaders64(IN const RAW_PE64* rpe, OUT PTR* SizeofHeaders);
#   pragma endregion
#   pragma region File
// these will only work on file aligned PEs
        LOGICAL LIBCALL PlAttachFile64(IN const void* const pFileBase, OUT RAW_PE64* rpe);
        LOGICAL LIBCALL PlDetachFile64(INOUT RAW_PE64* rpe);

        LOGICAL LIBCALL PlFileToImage64(IN const RAW_PE64* rpe, OUT VIRTUAL_MODULE64* vm);
        LOGICAL LIBCALL PlFileToImageEx64(IN const RAW_PE64* rpe, IN const void* pBuffer, OUT VIRTUAL_MODULE64* vm);

        LOGICAL LIBCALL PlCopyFile64(IN const RAW_PE64* rpe, OUT RAW_PE64* crpe);
        LOGICAL LIBCALL PlCopyFileEx64(IN const RAW_PE64* rpe, IN const void* pBuffer, OUT RAW_PE64* crpe);

        LOGICAL LIBCALL PlFreeFile64(INOUT RAW_PE64* rpe);

        LOGICAL LIBCALL PlReleaseImage64(INOUT VIRTUAL_MODULE64* vm);
#   pragma endregion
#   pragma region Virtual
// these will only work on image aligned PEs
        LOGICAL LIBCALL PlAttachImage64(IN const void* const pModuleBase, OUT VIRTUAL_MODULE64* vm);
        LOGICAL LIBCALL PlDetachImage64(INOUT VIRTUAL_MODULE64* vm);

        LOGICAL LIBCALL PlImageToFile64(IN const VIRTUAL_MODULE64* vm, OUT RAW_PE64* rpe);
        LOGICAL LIBCALL PlImageToFileEx64(IN const VIRTUAL_MODULE64* vm, IN const void* pBuffer, OUT RAW_PE64* rpe);

        LOGICAL LIBCALL PlCopyImage64(IN VIRTUAL_MODULE64* vm, OUT VIRTUAL_MODULE64* cvm);
        LOGICAL LIBCALL PlCopyImageEx64(IN VIRTUAL_MODULE64* vm, IN const void* pBuffer, OUT VIRTUAL_MODULE64* cvm);

        LOGICAL LIBCALL PlProtectImage64(INOUT VIRTUAL_MODULE64* vm);
        LOGICAL LIBCALL PlUnprotectImage64(INOUT VIRTUAL_MODULE64* vm);

        LOGICAL LIBCALL PlFreeImage64(INOUT VIRTUAL_MODULE64* vm);

        LOGICAL LIBCALL PlReleaseFile64(INOUT RAW_PE64* rpe);
#   pragma endregion
#pragma endregion