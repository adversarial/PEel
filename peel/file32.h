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
    LOGICAL EXPORT LIBCALL PlAttachFile32(IN const void* const pFileBase, OUT RAW_PE32* rpe);
    LOGICAL EXPORT LIBCALL PlDetachFile32(INOUT RAW_PE32* rpe);

    LOGICAL EXPORT LIBCALL PlFileToImage32(IN const RAW_PE32* rpe, OUT VIRTUAL_MODULE32* vm);
    LOGICAL EXPORT LIBCALL PlFileToImage32Ex(IN const RAW_PE32* rpe, IN const void* pBuffer, OUT VIRTUAL_MODULE32* vm);
    
    LOGICAL EXPORT LIBCALL PlCopyFile32(IN const RAW_PE32* rpe, OUT RAW_PE32* crpe);
    LOGICAL EXPORT LIBCALL PlCopyFile32Ex(IN const RAW_PE32* rpe, IN const void* pBuffer, OUT RAW_PE32* crpe);

    LOGICAL EXPORT LIBCALL PlFreeFile32(INOUT RAW_PE32* rpe);
#pragma endregion