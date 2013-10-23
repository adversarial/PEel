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

#include <stdint.h>
#include <Windows.h>

#pragma region Basic Types
    typedef uint32_t PTR32;
    typedef uint64_t PTR64;
#if SUPPORT_PE32PLUS
    typedef PTR64 PTR;
#else
    typedef PTR32 PTR;
#endif

// return system (too lazy for enums)
    typedef signed char LOGICAL;

#	define LOGICAL_SUCCESS(x) (!x)
#	define LOGICAL_FAILURE(x) (x > 0)
#	define LOGICAL_THIRD(x) (x < 0)

#	define LOGICAL_TRUE		(LOGICAL)0	// on success
#	define LOGICAL_FALSE	(LOGICAL)1	// on failure
#	define LOGICAL_MAYBE	(LOGICAL)-1	// on 3rd-party failure
#pragma endregion

#pragma region Windows Proxies
    #pragma region Types Defines
        typedef IMAGE_DOS_HEADER		 DOS_HEADER;
        typedef IMAGE_FILE_HEADER        FILE_HEADER;
        typedef IMAGE_OPTIONAL_HEADER32  OPTIONAL_HEADER32;
        typedef IMAGE_OPTIONAL_HEADER64  OPTIONAL_HEADER64;
        typedef IMAGE_NT_HEADERS32       NT_HEADERS32;
        typedef IMAGE_NT_HEADERS64		 NT_HEADERS64;
#if SUPPORT_PE32PLUS
        typedef NT_HEADERS64             NT_HEADERS;
#else
        typedef NT_HEADERS32             NT_HEADERS;
#endif
        typedef IMAGE_SECTION_HEADER	 SECTION_HEADER;
        typedef IMAGE_BASE_RELOCATION	 BASE_RELOCATION;
        typedef IMAGE_IMPORT_DESCRIPTOR  IMPORT_DESCRIPTOR;
        typedef IMAGE_THUNK_DATA32		 THUNK_DATA32;
        typedef IMAGE_THUNK_DATA64       THUNK_DATA64;
#if SUPPORT_PE32PLUS
        typedef THUNK_DATA64             THUNK_DATA;
#else
        typedef THUNK_DATA32             THUNK_DATA;
#endif
        typedef IMAGE_IMPORT_BY_NAME	 IMPORT_NAME;
        typedef IMAGE_EXPORT_DIRECTORY   EXPORT_DIRECTORY;
        typedef IMAGE_DEBUG_DIRECTORY    DEBUG_DIRECTORY;
        typedef IMAGE_RESOURCE_DIRECTORY RESOURCE_DIRECTORY;
        typedef IMAGE_RESOURCE_DIRECTORY_ENTRY RESOURCE_DIRECTORY_ENTRY;
        typedef IMAGE_RESOURCE_DATA_ENTRY RESOURCE_DATA_ENTRY;
        
        #define OPT_HDR_MAGIC32 IMAGE_NT_OPTIONAL_HDR32_MAGIC
        #define OPT_HDR_MAGIC64 IMAGE_NT_OPTIONAL_HDR64_MAGIC
#if SUPPORT_PE32PLUS
        #define OPT_HDR_MAGIC OPT_HDR_MAGIC64
#else
        #define OPT_HDR_MAGIC OPT_HDR_MAGIC32
#endif
    #pragma endregion
#pragma endregion