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

// this header may be out of date

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
        typedef PTR32 PTR;

        typedef signed char LOGICAL;

#   	define LOGICAL_SUCCESS(x) (!x)
#   	define LOGICAL_FAILURE(x) (x > 0)
#   	define LOGICAL_THIRD(x) (x < 0)

#   	define LOGICAL_TRUE		(LOGICAL)0	// on success
#   	define LOGICAL_FALSE	(LOGICAL)1	// on failure
#   	define LOGICAL_MAYBE	(LOGICAL)-1	// on 3rd-party failure
#   pragma endregion

#   pragma region Windows Proxies
        typedef IMAGE_DOS_HEADER		 DOS_HEADER;
        typedef IMAGE_NT_HEADERS32		 NT_HEADERS32;
        typedef IMAGE_NT_HEADERS64		 NT_HEADERS64;
        typedef IMAGE_NT_HEADERS		 NT_HEADERS;
        typedef IMAGE_SECTION_HEADER	 SECTION_HEADER;
        typedef IMAGE_BASE_RELOCATION	 BASE_RELOCATION;
        typedef IMAGE_IMPORT_DESCRIPTOR  IMPORT_DESCRIPTOR;
        typedef IMAGE_THUNK_DATA32		 THUNK_DATA32;
        typedef IMAGE_IMPORT_BY_NAME	 IMPORT_NAME;
        typedef IMAGE_EXPORT_DIRECTORY   EXPORT_DIRECTORY;
        typedef IMAGE_DEBUG_DIRECTORY    DEBUG_DIRECTORY;
        typedef IMAGE_RESOURCE_DIRECTORY RESOURCE_DIRECTORY;
        typedef IMAGE_RESOURCE_DIRECTORY_ENTRY RESOURCE_DIRECTORY_ENTRY;
        typedef IMAGE_RESOURCE_DIRECTORY_STRING RESOURCE_DIRECTORY_STRING;
        typedef IMAGE_RESOURCE_DIR_STRING_U RESOURCE_DIR_STRING_U;
#   pragma endregion
#pragma endregion

#pragma region Structs
#	pragma pack(push, 1)

        typedef struct {
            BYTE Stub[0x0e];	// 16bit stub
            char dsMsg[0x2a];	// variable size, 2a is default msvc, '$' terminated
        } DOS_STUB;
        
        typedef struct { // ptr size for alignment, can be adjusted if necessary
            PTR     Relocated : 1,	// relocations are resolved
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
        } CODECAVE_LIST32;	    // stores data that was in padding/outside of sections

        typedef struct {
            char  *Name,          // ptr to function name (NULL if by ordinal)
                  *Ordinal;       // ptr to DWORD ordinal number (NULL if by name)
            PTR32 *dwItemPtr;     // ptr to IAT entry
            void  *Flink;
        } IMPORT_ITEM32;

        typedef struct {
            char          *Library; // ptr to char* that hold library name
            IMPORT_ITEM32 *iiImportList;
            void          *Flink;
        } IMPORT_LIBRARY32;

        typedef struct {
            char  *Name,
                  *Ordinal;
            PTR32 *dwItemPtr;
            void  *Flink;
        } EXPORT_LIST32;

        typedef struct {
            char  *Name;
            PTR    wId; // only use lower WORD
            PTR32 *dwDataPtr;
            void  *Flink;
        } RESOURCE_ITEM32;

        typedef struct {
            DWORD  dwType;
            RESOURCE_ITEM32 *riResourceList; // ptr to forward-linked list of resources of dwType
            void  *Flink;                    // points to RESOURCE_LIST32 of next type
        } RESOURCE_LIST32;

        typedef struct {
            DOS_HEADER		 *pIDH;
            DOS_STUB 		 *pIDS;
            NT_HEADERS32 	 *pINH;
            SECTION_HEADER  **ppISH;		    // array pointing to section headers
            void		    **ppSectionData;    // array pointing to section data
            PE_FLAGS		  dwFlags;
// essentials (pointers only)
// the following allocate memory and, however are only used when their respective functions are called
            CODECAVE_LIST32  *pCaveData;	    // forward-linked list containing codecaves
            IMPORT_LIBRARY32 *pIL;              // forward-linked list of imports
            EXPORT_LIST32    *pEI;              // forward-linked list of exports
            RESOURCE_LIST32  *pRI;              // forward-linked list of resources
        } RAW_PE32;	// contains PE file

        typedef struct {
            RAW_PE32	PE;
            void	   *Flink,
                       *Blink;
            char		cName[8];	// identification of loaded DLLS, not sz
            void*		pBaseAddr;	// if headers aren't loaded
        } VIRTUAL_MODULE32;	// wrapper to represent aligned PE

#   pragma pack(pop)
#pragma endregion

#pragma region Prototypes
#   pragma region Standard
        PTR32 LIBCALL MrAlignUp32(IN const PTR32 offset, IN const PTR32 alignment);
        PTR32 LIBCALL MrAlignDown32(IN const PTR32 offset, IN const PTR32 alignment);
    
        DWORD LIBCALL MrSectionToPageProtection32(IN const DWORD dwCharacteristics);
        DWORD LIBCALL MrPageToSectionProtection32(IN DWORD dwProtection);
#   pragma endregion
#   pragma region Raw
// these can operate on any filled RAW_PE regardless of alignment
        LOGICAL LIBCALL MrRvaToPa32(IN const RAW_PE32* rpe, IN const PTR32 Rva, OUT PTR32* Pa);
        LOGICAL LIBCALL MrPaToRva32(IN const RAW_PE32* rpe, IN const PTR32 Pa, OUT PTR32* Rva);

        LOGICAL LIBCALL MrGetRvaPtr32(IN const RAW_PE32* rpe, IN const PTR32 Rva, OUT PTR* Ptr);
        LOGICAL LIBCALL MrGetPaPtr32(IN const RAW_PE32* rpe, IN const PTR32 Pa, OUT PTR* Ptr);

        LOGICAL LIBCALL MrWriteRva32(INOUT RAW_PE32* rpe, IN const PTR32 Rva, IN const void* pData, IN size_t cbData);
        LOGICAL LIBCALL MrReadRva32(IN const RAW_PE32* rpe, IN const PTR32 Rva, IN void* pBuffer, IN size_t cbBufferMax);
        LOGICAL LIBCALL MrWritePa32(INOUT RAW_PE32* rpe, IN const PTR32 Pa, IN const void* pData, IN size_t cbData);
        LOGICAL LIBCALL MrReadPa32(IN const RAW_PE32* rpe, IN const PTR32 Pa, IN void* pBuffer, IN size_t cbBufferMax);

        LOGICAL LIBCALL MrRvaToVa32(IN const VIRTUAL_MODULE32* vm, IN const PTR32 Rva, OUT PTR32* Va);
        LOGICAL LIBCALL MrPaToVa32(IN const VIRTUAL_MODULE32* vm, IN const PTR32 Pa, OUT PTR32* Va);

        LOGICAL LIBCALL MrMaxPa32(IN const RAW_PE32* rpe, OUT PTR32* MaxPa);
        LOGICAL LIBCALL MrMaxRva32(IN const RAW_PE32* rpe, OUT PTR32* MaxRva);
    
        LOGICAL LIBCALL MrEnumerateImports32(INOUT RAW_PE32* rpe);
        LOGICAL LIBCALL MrEnumerateExports32(INOUT RAW_PE32* rpe);
        LOGICAL LIBCALL MrEnumerateResources32(INOUT RAW_PE32* rpe);
#   pragma endregion
#   pragma region File
// these will only work on file aligned PEs
        LOGICAL LIBCALL MrAttachFile32(IN const void* const pFileBase, OUT RAW_PE32* rpe);
        LOGICAL LIBCALL MrDetachFile32(INOUT RAW_PE32* rpe);

        LOGICAL LIBCALL MrFileToImage32(IN const RAW_PE32* rpe, OUT VIRTUAL_MODULE32* vm);
        LOGICAL LIBCALL MrFileToImage32Ex(IN const RAW_PE32* rpe, IN const void* pBuffer, OUT VIRTUAL_MODULE32* vm);

        LOGICAL LIBCALL MrCopyFile32(IN const RAW_PE32* rpe, OUT RAW_PE32* crpe);
        LOGICAL LIBCALL MrCopyFile32Ex(IN const RAW_PE32* rpe, IN const void* pBuffer, OUT RAW_PE32* crpe);

        LOGICAL LIBCALL MrFreeFile32(INOUT RAW_PE32* rpe);
#   pragma endregion
#   pragma region Virtual
// these will only work on image aligned PEs
        LOGICAL LIBCALL MrAttachImage32(IN const void* const pModuleBase, OUT VIRTUAL_MODULE32* vm);
        LOGICAL LIBCALL MrDetachImage32(INOUT VIRTUAL_MODULE32* vm);

        LOGICAL LIBCALL MrImageToFile32(IN const VIRTUAL_MODULE32* vm, OUT RAW_PE32* rpe);
        LOGICAL LIBCALL MrImageToFile32Ex(IN const VIRTUAL_MODULE32* vm, IN const void* pBuffer, OUT RAW_PE32* rpe);

        LOGICAL LIBCALL MrCopyImage32(IN VIRTUAL_MODULE32* vm, OUT VIRTUAL_MODULE32* cvm);
        LOGICAL LIBCALL MrCopyImage32Ex(IN VIRTUAL_MODULE32* vm, IN const void* pBuffer, OUT VIRTUAL_MODULE32* cvm);

        LOGICAL LIBCALL MrFreeImage32(INOUT VIRTUAL_MODULE32* vm);
#   pragma endregion
#pragma endregion