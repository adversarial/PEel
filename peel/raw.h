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

#include "peel.h"

#pragma region File image functions
    // conversions
    LOGICAL EXPORT LIBCALL PlRvaToPa(IN const RAW_PE* rpe, IN const PTR Rva, OUT PTR* Pa);
    LOGICAL EXPORT LIBCALL PlPaToRva(IN const RAW_PE* rpe, IN const PTR Pa, OUT PTR* Rva);

    // editing (using RVA because it's the most common I use and easy to convert once loaded)
    LOGICAL EXPORT LIBCALL PlGetRvaPtr(IN const RAW_PE* rpe, IN const PTR Rva, OUT PTR* Ptr);
    LOGICAL EXPORT LIBCALL PlGetPaPtr(IN const RAW_PE* rpe, IN const PTR Pa, OUT PTR* Ptr);

    LOGICAL EXPORT LIBCALL PlWriteRva(INOUT RAW_PE* rpe, IN const PTR Rva, IN const void* pData, IN size_t cbData);
    LOGICAL EXPORT LIBCALL PlReadRva(IN const RAW_PE* rpe, IN const PTR Rva, IN void* pBuffer, IN size_t cbBufferMax);

    // these end up calling PlXxxRva32
    LOGICAL EXPORT LIBCALL PlWritePa(INOUT RAW_PE* rpe, IN const PTR Pa, IN const void* pData, IN size_t cbData);
    LOGICAL EXPORT LIBCALL PlReadPa(IN const RAW_PE* rpe, IN const PTR Pa, IN void* pBuffer, IN size_t cbBufferMax);

    // virtual to rva... come on, guys?
    LOGICAL EXPORT LIBCALL PlRvaToVa(IN const VIRTUAL_MODULE* vm, IN const PTR Rva, OUT PTR* Va);
    LOGICAL EXPORT LIBCALL PlPaToVa(IN const VIRTUAL_MODULE* vm, IN const PTR Pa, OUT PTR* Va);

    // fact checking?
    LOGICAL EXPORT LIBCALL PlMaxPa(IN const RAW_PE* rpe, OUT PTR* MaxPa);
    LOGICAL EXPORT LIBCALL PlMaxRva(IN const RAW_PE* rpe, OUT PTR* MaxRva);
    
    // imports/exports
    LOGICAL EXPORT LIBCALL PlEnumerateImports(INOUT RAW_PE* rpe);
    LOGICAL EXPORT LIBCALL PlFreeEnumeratedImports(INOUT RAW_PE* rpe);

    LOGICAL EXPORT LIBCALL PlEnumerateExports(INOUT RAW_PE* rpe);
    LOGICAL EXPORT LIBCALL PlFreeEnumeratedExports(INOUT RAW_PE* rpe);

    LOGICAL EXPORT LIBCALL PlRelocate(INOUT RAW_PE* rpe, IN const PTR dwOldBase, IN const PTR dwNewBase);
    
    LOGICAL EXPORT LIBCALL PlCalculateChecksum(INOUT RAW_PE* rpe, OUT DWORD* dwChecksum);
#pragma endregion