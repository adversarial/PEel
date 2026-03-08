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

#include "..\..\peel\peel.h"
#include <Windows.h>
#include <winternl.h>
#include <stddef.h>
#include <string.h>

#ifdef _M_IX86
	#define x86 TRUE
#else
	#define x86 FALSE
#endif

#pragma region Structs
#   pragma pack(push, 4)
	    typedef struct _CURRENT_DIRECTORY {
		     UNICODE_STRING DosPath;
		     PVOID Handle;
	    } CURDIR; 

	    typedef struct _RTL_USER_PROCESS_PARAMETERS_X {
		     ULONG MaximumLength;
		     ULONG Length;
		     ULONG Flags;
		     ULONG DebugFlags;
		     PVOID ConsoleHandle;
		     ULONG ConsoleFlags;
		     PVOID StandardInput;
		     PVOID StandardOutput;
		     PVOID StandardError;
		     CURDIR CurrentDirectory;
		     UNICODE_STRING DllPath;
		     UNICODE_STRING ImagePathName;
		     UNICODE_STRING CommandLine;
		     PVOID Environment;
		     ULONG StartingX;
		     ULONG StartingY;
		     ULONG CountX;
		     ULONG CountY;
		     ULONG CountCharsX;
		     ULONG CountCharsY;
		     ULONG FillAttribute;
		     ULONG WindowFlags;
		     ULONG ShowWindowFlags;
		     UNICODE_STRING WindowTitle;
		     UNICODE_STRING DesktopInfo;
		     UNICODE_STRING ShellInfo;
		     UNICODE_STRING RuntimeData;
	    } PROCESS_PARAMETERS;

        typedef struct _PEB_LDR_MODULE32 {
            LIST_ENTRY              InLoadOrderModuleList;
            LIST_ENTRY              InMemoryOrderModuleList;
            LIST_ENTRY              InInitializationOrderModuleList;
            PVOID                   BaseAddress;
            PVOID                   EntryPoint;
            ULONG                   SizeOfImage;
            UNICODE_STRING          FullDllName;
            UNICODE_STRING          BaseDllName;
            ULONG                   Flags;
            SHORT                   LoadCount;
            SHORT                   TlsIndex;
            LIST_ENTRY              HashTableEntry;
            ULONG                   TimeDateStamp;
        } LDR_MODULE32;

        typedef struct {
            BYTE Reserved1[2];
            BYTE BeingDebugged;
            BYTE Reserved2[1];
            PTR32 Reserved3[2];
            PPEB_LDR_DATA Ldr;
            PTR32 ProcessParameters;
            BYTE Reserved4[104];
            PTR32 Reserved5[52];
            PTR32 PostProcessInitRoutine;
            BYTE Reserved6[128];
            PTR32 Reserved7[1];
            ULONG SessionId;
        } PEB32;

#   pragma pack(pop)
#pragma endregion

#pragma region Prototypes
    void*         EXPORT LIBCALL KpGetCurrentPeb();
	void*		  EXPORT LIBCALL TEB* KpGetCurrentTib();
    LDR_MODULE32* EXPORT LIBCALL KpGetLdrModule(IN const wchar_t* wzName);
    
	wchar_t*      EXPORT LIBCALL KpGetEnvironmentVariable(IN const PEB* pPeb, IN const wchar_t* wzVar);

	wchar_t*	  EXPORT LIBCALL KpGetFilePath(IN const PEB* pPeb);
	DWORD		  EXPORT LIBCALL KpGetCurrentProcessId(IN const TEB* pTeb);
	DWORD		  EXPORT LIBCALL KpGetCurrentThreadId(IN const TEB* pTeb);
	DWORD		  EXPORT LIBCALL KpGetLastError(IN const TEB* pTeb);
	HANDLE		  EXPORT LIBCALL KpGetStdHandle(IN const PEB* pPeb, const DWORD nStdHandle);
#pragma endregion