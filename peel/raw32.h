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
    LOGICAL EXPORT LIBCALL MrRvaToPa32(IN const RAW_PE32* rpe, IN const PTR32 Rva, OUT PTR32* Pa);
    LOGICAL EXPORT LIBCALL MrPaToRva32(IN const RAW_PE32* rpe, IN const PTR32 Pa, OUT PTR32* Rva);

    // editing (using RVA because it's the most common I use and easy to convert once loaded)
    LOGICAL EXPORT LIBCALL MrGetRvaPtr32(INOUT const RAW_PE32* rpe, IN const PTR32 Rva, OUT PTR* Ptr);

    LOGICAL EXPORT LIBCALL MrWriteRva32(INOUT RAW_PE32* rpe, IN const PTR32 Rva, IN const void* pData, IN size_t cbData);
    LOGICAL EXPORT LIBCALL MrReadRva32(IN const RAW_PE32* rpe, IN const PTR32 Rva, IN void* pBuffer, IN size_t cbBufferMax);
    // these end up calling MrXxxRva32
    LOGICAL EXPORT LIBCALL MrWritePa32(INOUT RAW_PE32* rpe, IN const PTR32 Pa, IN const void* pData, IN size_t cbData);
    LOGICAL EXPORT LIBCALL MrReadPa32(IN const RAW_PE32* rpe, IN const PTR32 Pa, IN void* pBuffer, IN size_t cbBufferMax);

    // virtual to rva... come on, guys?
    LOGICAL EXPORT LIBCALL MrRvaToVa32(IN const VIRTUAL_MODULE32* vm, IN const PTR32 Rva, OUT PTR32* Va);
    LOGICAL EXPORT LIBCALL MrPaToVa32(IN const VIRTUAL_MODULE32* vm, IN const PTR32 Pa, OUT PTR32* Va);

    // fact checking?
    LOGICAL EXPORT LIBCALL MrMaxPa32(IN const RAW_PE32* rpe, OUT PTR32* MaxPa);
    LOGICAL EXPORT LIBCALL MrMaxRva32(IN const RAW_PE32* rpe, OUT PTR32* MaxRva);
    
    // imports/relocations
    LOGICAL EXPORT LIBCALL MrEnumerateImports32(INOUT RAW_PE32* rpe);

    // codecaving
    //LOGICAL EXPORT LIBCALL MrDiscoverCaves32(INOUT RAW_PE32* rpe);
    //LOGICAL EXPORT LIBCALL MrFreeCaves32(INOUT RAW_PE32* rpe);
    //LOGICAL EXPORT LIBCALL MrShedCaves32(INOUT RAW_PE32* rpe);
#pragma endregion