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

#include <stdint.h>
#include <Windows.h>

#pragma region Basic Types
    typedef uint32_t PTR32;
    typedef uint64_t PTR64;
    typedef PTR32 PTR;

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
        typedef IMAGE_RESOURCE_DATA_ENTRY RESOURCE_DATA_ENTRY;
    #pragma endregion
#pragma endregion