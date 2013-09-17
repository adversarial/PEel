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
    LOGICAL EXPORT LIBCALL PlAttachImage64(IN const void* const pModuleBase, OUT VIRTUAL_MODULE64* vm);
    LOGICAL EXPORT LIBCALL PlDetachImage64(INOUT VIRTUAL_MODULE64* vm);

    LOGICAL EXPORT LIBCALL PlImageToFile64(IN const VIRTUAL_MODULE64* vm, OUT RAW_PE64* rpe);
    LOGICAL EXPORT LIBCALL PlImageToFile64Ex(IN const VIRTUAL_MODULE64* vm, IN const void* pBuffer, OUT RAW_PE64* rpe);

    LOGICAL EXPORT LIBCALL PlCopyImage64(IN VIRTUAL_MODULE64* vm, OUT VIRTUAL_MODULE64* cvm);
    LOGICAL EXPORT LIBCALL PlCopyImage64Ex(IN VIRTUAL_MODULE64* vm, IN const void* pBuffer, OUT VIRTUAL_MODULE64* cvm);

    LOGICAL EXPORT LIBCALL PlProtectImage64(INOUT VIRTUAL_MODULE64* vm);
    LOGICAL EXPORT LIBCALL PlUnprotectImage64(INOUT VIRTUAL_MODULE64* vm);

    LOGICAL EXPORT LIBCALL PlFreeImage64(INOUT VIRTUAL_MODULE64* vm);
#pragma endregion