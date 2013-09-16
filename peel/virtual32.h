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
    LOGICAL EXPORT LIBCALL PlAttachImage32(IN const void* const pModuleBase, OUT VIRTUAL_MODULE32* vm);
    LOGICAL EXPORT LIBCALL PlDetachImage32(INOUT VIRTUAL_MODULE32* vm);

    LOGICAL EXPORT LIBCALL PlImageToFile32(IN const VIRTUAL_MODULE32* vm, OUT RAW_PE32* rpe);
    LOGICAL EXPORT LIBCALL PlImageToFile32Ex(IN const VIRTUAL_MODULE32* vm, IN const void* pBuffer, OUT RAW_PE32* rpe);

    LOGICAL EXPORT LIBCALL PlCopyImage32(IN VIRTUAL_MODULE32* vm, OUT VIRTUAL_MODULE32* cvm);
    LOGICAL EXPORT LIBCALL PlCopyImage32Ex(IN VIRTUAL_MODULE32* vm, IN const void* pBuffer, OUT VIRTUAL_MODULE32* cvm);

    LOGICAL EXPORT LIBCALL PlProtectImage32(INOUT VIRTUAL_MODULE32* vm);
    LOGICAL EXPORT LIBCALL PlUnprotectImage32(INOUT VIRTUAL_MODULE32* vm);

    LOGICAL EXPORT LIBCALL PlFreeImage32(INOUT VIRTUAL_MODULE32* vm);
#pragma endregion