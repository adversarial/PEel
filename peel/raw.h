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

    LOGICAL EXPORT LIBCALL PlSizeofPeHeaders(IN const RAW_PE* rpe, OUT PTR* SizeofHeaders);
#pragma endregion
