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

#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>

#undef TRUE
#undef FALSE
#define TRUE  1
#define FALSE 0
#define MAX_SECTIONS 0x100      // don't load any more sections

#pragma region Build Options
#   ifdef _MSC_VER         // we don't compile with msvc
#       define SUPPORT_PE32PLUS             FALSE
#   endif
#	define EXPORT_ALL_FUNCTIONS				TRUE	// FALSE will include only basic mode items
#	define LOAD_LEGIT						TRUE	// Register module with PEB::LdrList
#	define SHED_CODECAVES					TRUE	// Shed anything that is hiding in padding (and rich)
#	define USE_NATIVE_FUNCTIONS				TRUE	// will attempt to use native functions (only windoze)
#	define NO_CRT							FALSE	// plz use
#	define ACCEPT_INVALID_SIGNATURES		TRUE	// ignore magic and checksums

#	define MAX_DBG_STRING_LEN				0x100	// max strlen
#	define LIBCALL							__stdcall // go ahead and use whatevs

#pragma endregion

///////////////////////////////////////////////////////////////////////////////
// DO NOT EDIT BELOW THIS LINE ////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#pragma region DevEnable
#	define X64_COMPATIBLE_YET				FALSE
#	define HIDE_EXPORTS_PLZ					FALSE   // why is this even here
#	define BASIC_MODE						FALSE	// only exports viewing functions
#pragma endregion

#pragma region Environment
#   ifdef _MSC_VER
#       ifndef NDEBUG
#	    define DEBUGMODE						TRUE
#	    endif
#   endif
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
#pragma endregion

#pragma region Private
// Watermark
/*
#ifndef _WATERMARK
#define _WATERMARK
static char szWatermark[] = "PEel v1.0 by x8esix"; // please don't remove, it's 22 bytes
#if SUPPORT_PE32
static char szWatermark[] = "PE32";
#else
static char szWatermark[] = "PE64";
#endif
#endif
*/
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
#	if NO_CRT || USE_NATIVE_FUNCTIONS
#       ifdef BUILDING_FOR_THE_WIN
#		    undef malloc
#		    undef calloc
#		    undef realloc
#		    undef free

#		    define malloc(cbSize) HeapAlloc(GetProcessHeap(), 0, (cbSize))
#		    define calloc(iNum, cbSize) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (iNum * cbSize))
#		    define realloc(pMem, cbNewSize) HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (pMem), (cbNewSize))
#		    define free(pMem) HeapFree(GetProcessHeap(), 0, (pMem))
#       endif
#   endif
#pragma endregion