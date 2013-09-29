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

#pragma region File functions
    LOGICAL EXPORT LIBCALL PlAttachFile(IN const void* const pFileBase, OUT RAW_PE* rpe);
    LOGICAL EXPORT LIBCALL PlDetachFile(INOUT RAW_PE* rpe);

    LOGICAL EXPORT LIBCALL PlFileToImage(IN const RAW_PE* rpe, OUT VIRTUAL_MODULE* vm);
    LOGICAL EXPORT LIBCALL PlFileToImageEx(IN const RAW_PE* rpe, IN const void* pBuffer, OUT VIRTUAL_MODULE* vm);
    
    LOGICAL EXPORT LIBCALL PlCopyFile(IN const RAW_PE* rpe, OUT RAW_PE* crpe);
    LOGICAL EXPORT LIBCALL PlCopyFileEx(IN const RAW_PE* rpe, IN const void* pBuffer, OUT RAW_PE* crpe);

    LOGICAL EXPORT LIBCALL PlFreeFile(INOUT RAW_PE* rpe);
#pragma endregion