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

#pragma region Virtual Image functions
    LOGICAL EXPORT LIBCALL PlAttachImage(IN const void* const pModuleBase, OUT VIRTUAL_MODULE* vm);
    LOGICAL EXPORT LIBCALL PlDetachImage(INOUT VIRTUAL_MODULE* vm);

    LOGICAL EXPORT LIBCALL PlImageToFile(IN const VIRTUAL_MODULE* vm, OUT RAW_PE* rpe);
    LOGICAL EXPORT LIBCALL PlImageToFileEx(IN const VIRTUAL_MODULE* vm, IN const void* pBuffer, OUT RAW_PE* rpe);

    LOGICAL EXPORT LIBCALL PlCopyImage(IN VIRTUAL_MODULE* vm, OUT VIRTUAL_MODULE* cvm);
    LOGICAL EXPORT LIBCALL PlCopyImageEx(IN VIRTUAL_MODULE* vm, IN const void* pBuffer, OUT VIRTUAL_MODULE* cvm);

    LOGICAL EXPORT LIBCALL PlProtectImage(INOUT VIRTUAL_MODULE* vm);
    LOGICAL EXPORT LIBCALL PlUnprotectImage(INOUT VIRTUAL_MODULE* vm);

    LOGICAL EXPORT LIBCALL PlFreeImage(INOUT VIRTUAL_MODULE* vm);

    LOGICAL EXPORT LIBCALL PlReleaseImage(INOUT VIRTUAL_MODULE* vm);
#pragma endregion