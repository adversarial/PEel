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

    32 bit only

    HlpXxx functions aim to help the loading of PE files with PEel by
    abstracting and automating details. Windows specific implementations
    only, sorry. Only kernel32.dll is imported.
    by x8esix
 */
#include "..\..\peel\peel.h"
#include <winternl.h>
#include <intrin.h>

#pragma region Prototypes
    LOGICAL EXPORT LIBCALL HlpLoadAndBurn(IN const void* pLibrary, OUT VIRTUAL_MODULE32* vmOut);
    LOGICAL EXPORT LIBCALL HlpLoadAndBurnEx(IN const VIRTUAL_MODULE32* vmIn, OUT VIRTUAL_MODULE32* vmOut);
    LOGICAL EXPORT LIBCALL HlpReplaceImage(INOUT VIRTUAL_MODULE32* vmTarget, IN VIRTUAL_MODULE32* vmReplacement, OUT VIRTUAL_MODULE32* vmClone);
    LOGICAL EXPORT LIBCALL HlpFreeBurnedLibrary(INOUT VIRTUAL_MODULE* vm);
    LOGICAL EXPORT LIBCALL HlpResolveImportsWinApi(INOUT VIRTUAL_MODULE* vm);
    LOGICAL EXPORT LIBCALL HlpResolveImports(INOUT VIRTUAL_MODULE* vm);
    LOGICAL EXPORT LIBCALL HlpAddSectionHeader(INOUT RAW_PE* rpe, IN SECTION_HEADER* pshIn);
    #pragma endregion

#pragma region Constants
#   define MAX_SYSPATH 512
#pragma endregion