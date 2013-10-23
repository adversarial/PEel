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

#pragma region File functions
    LOGICAL EXPORT LIBCALL PlAttachFile(IN const void* const pFileBase, OUT RAW_PE* rpe);
    LOGICAL EXPORT LIBCALL PlDetachFile(INOUT RAW_PE* rpe);

    LOGICAL EXPORT LIBCALL PlFileToImage(IN const RAW_PE* rpe, OUT VIRTUAL_MODULE* vm);
    LOGICAL EXPORT LIBCALL PlFileToImageEx(IN const RAW_PE* rpe, IN const void* pBuffer, OUT VIRTUAL_MODULE* vm);
    
    LOGICAL EXPORT LIBCALL PlCopyFile(IN const RAW_PE* rpe, OUT RAW_PE* crpe);
    LOGICAL EXPORT LIBCALL PlCopyFileEx(IN const RAW_PE* rpe, IN const void* pBuffer, OUT RAW_PE* crpe);

    LOGICAL EXPORT LIBCALL PlFreeFile(INOUT RAW_PE* rpe);

    LOGICAL EXPORT LIBCALL PlReleaseFile(INOUT RAW_PE* rpe);
#pragma endregion