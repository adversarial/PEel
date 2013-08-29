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

/*
    Hlp: High-Level PEel functions

    HlpXxx functions aim to help the loading of PE files with PEel by
    abstracting and automating details. Windows specific implementations
    only, sorry :(
    by x8esix
 */
#include "peel.h"
#include <winternl.h>
#include <SubAuth.h>

#pragma region Structs
    typedef struct {
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
        PVOID Reserved3[2];
        PPEB_LDR_DATA Ldr;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
        BYTE Reserved4[104];
        PVOID Reserved5[52];
        PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
        BYTE Reserved6[128];
        PVOID Reserved7[1];
        ULONG SessionId;
    } PEB32;
#pragma endregion

#pragma region Prototypes
    void* EXPORT LIBCALL HlpGetCurrentPeb();

    LOGICAL EXPORT LIBCALL HlpReplaceImage32Ex(INOUT VIRTUAL_MODULE32* vmTarget, IN VIRTUAL_MODULE32* vmReplacement, OUT VIRTUAL_MODULE32* vmClone);
#pragma endregion