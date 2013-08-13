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

#include <Windows.h>

#define TRUE 1
#define FALSE 0

#pragma region Build Options
#	define EXPORT_ALL_FUNCTIONS				TRUE	// FALSE will include only basic mode items
#	define LOAD_LEGIT						FALSE	// Register module with PEB::LdrList
#	define SHED_CODECAVES					TRUE	// Shed anything that is hiding in padding (and rich)
#	define USE_NATIVE_FUNCTIONS				TRUE	// will attempt to use native functions (only windoze)
#	define NO_CRT							TRUE	// plz use
#	define ACCEPT_INVALID_SIGNATURES		TRUE	// ignore magic and checksums

#	define MAX_DBG_STRING_LEN				0x100	// max strlen
#	define LIBCALL							__stdcall // go ahead and use whatevs

#pragma endregion

///////////////////////////////////////////////////////////////////////////////
// DO NOT EDIT BELOW THIS LINE ////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#pragma region DevEnable
#	define X64_COMPATIBLE_YET				FALSE
#	define HIDE_EXPORTS_PLZ					FALSE
#	define BASIC_MODE						FALSE	// only exports viewing functions
#pragma endregion

#pragma region Environment
#	ifndef NDEBUG
#	define DEBUGMODE						TRUE
#	endif
#	ifdef _DLL
#		define EXPORT_FUNCTIONS_SUPPORTED	TRUE
#	else
#		define EXPORT_FUNCTIONS_SUPPORTED	FALSE
#	endif
#	ifdef _WIN32
#		define BUILDING_FOR_THE_WIN			TRUE
#	endif
#	ifdef _M_IX86
#		define BUILDING_AS_X86				TRUE
#	else
#		if ! X64_COMPATIBLE_YET
#			error Not x64 compatible!
#		endif
#		define BUILDING_AS_X64				TRUE
#	endif
#   define _CRT_SECURE_NO_WARNINGS
#pragma endregion

#pragma region Private
// Watermark
static char szWatermark[] = "PEel v0.1 by karmabis"; // please don't remove, it's 22 bytes
// Commentary
#	define IN			// usu const
#	define OUT			// ptr content will be modified
#	define INOUT		// ptr content required and then modified
#	define OPT			// can be NULL/0
// DLL exporting
#	if EXPORTED_FUNCTIONS_SUPPORTED && EXPORT_FUNCTIONS && !HIDE_EXPORTS_PLZ
#		define EXPORT __declspec(dllexport)
#	else
#		define EXPORT
#	endif
// Custom CRT in milk
#	if NO_CRT
#		undef malloc
#		undef calloc
#		undef realloc
#		undef free

#		define malloc(cbSize) HeapAlloc(GetProcessHeap(), 0, (cbSize))
#		define calloc(iNum, cbSize) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (iNum * cbSize))
#		define realloc(pMem, cbNewSize) HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (pMem), (cbNewSize))
#		define free(pMem) HeapFree(GetProcessHeap(), 0, (pMem))
#	endif
#pragma endregion