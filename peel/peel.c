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

#include "peel.h"

#ifdef DEBUGMODE
    /// <summary>
    ///	Outputs formatted debug string </summary>
    ///
    /// <param name="rpe">
    /// Format string (max len formatted = MAX_DBG_STRING_LEN </param>
    ///
    /// <returns>
    /// None </returns>
    LOGICAL CDECL MrDebugOut(IN const TCHAR* tzFormat, ...) {
        TCHAR tzMsg[MAX_DBG_STRING_LEN];
        va_list vaList = NULL;

        va_start(vaList, tzFormat);
        _vsntprintf(tzMsg, MAX_DBG_STRING_LEN - 1, (LPCTSTR)tzFormat, vaList);
        OutputDebugString(tzMsg);
        va_end(vaList);
        return LOGICAL_TRUE;
    }
#endif

/// <summary>
///	Calculates aligned virtual size </summary>
///
/// <param name="offset">
/// Address to align </param>
/// <param name="alignment">
/// Align up to </param>
///
/// <returns>
/// Rounded value </returns>
PTR32 EXPORT LIBCALL MrAlignUp32(IN const PTR32 offset, IN const PTR32 alignment) {
    if (!alignment)
        return offset;
    return (offset + alignment - 1) & -(alignment);
}

/// <summary>
///	Calculates aligned virtual size </summary>
///
/// <param name="offset">
/// Address to align </param>
/// <param name="alignment">
/// Align down to </param>
///
/// <returns>
/// Rounded value </returns>
PTR32 EXPORT LIBCALL MrAlignDown32(IN const PTR32 offset, IN const PTR32 alignment) {
    if (!alignment)
        return offset;
    return (offset & -(alignment));
}

/// <summary>
///	Calculates aligned virtual size </summary>
///
/// <param name="offset">
/// Address to align </param>
/// <param name="alignment">
/// Align up to </param>
///
/// <returns>
/// Rounded value </returns>
PTR64 EXPORT LIBCALL MrAlignUp64(IN const PTR64 offset, IN const PTR64 alignment) {
    if (!alignment)
        return offset;
    return (offset + alignment - 1) & -(alignment);
}

/// <summary>
///	Calculates aligned virtual size </summary>
///
/// <param name="offset">
/// Address to align </param>
/// <param name="alignment">
/// Align down to </param>
///
/// <returns>
/// Rounded value </returns>
PTR64 EXPORT LIBCALL MrAlignDown64(IN const PTR64 offset, IN const PTR64 alignment) {
    if (!alignment)
        return offset;
    return (offset & -(alignment));
}


/// <summary>
///	Converts section protection in SECTION_HEADER::Characteristics to page protection </summary>
///
/// <param name="dwCharacteristics">
/// SECTION_HEADER::Characteristics
///
/// <returns>
/// Page protection for use with VirtualProtect </returns>
DWORD EXPORT LIBCALL MrSectionToPageProtection(IN const DWORD dwCharacteristics) {
    DWORD dwProtect = dwCharacteristics;
    
    if (dwProtect & IMAGE_SCN_CNT_CODE)
        dwProtect |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    if (dwProtect & IMAGE_SCN_CNT_INITIALIZED_DATA
     || dwProtect & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
     dwProtect |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    // 1st bit is mem_shared, ignore it, #idgaf about r0
    dwProtect = (dwProtect >> (3 * CHAR_BIT + 5)) & 0xff;
    switch (dwProtect) {
        case 1: // execute
            dwProtect = PAGE_EXECUTE;
            break;
        case 2: // read
            dwProtect = PAGE_READONLY;
            break;
        case 3: // execute read
            dwProtect = PAGE_EXECUTE_READ;
            break;
        case 4: // write (???)
        case 6: // read write
            dwProtect = PAGE_READWRITE;
            break;
        case 5: // execute write (???)
        case 7: // all access
            dwProtect = PAGE_EXECUTE_READWRITE;
        default:
            dwProtect = PAGE_NOACCESS;
            break;
    }
    if (dwCharacteristics & IMAGE_SCN_MEM_NOT_CACHED)
        dwProtect |= PAGE_NOCACHE;
    return dwProtect;
}

/// <summary>
///	Converts page protection constant to SECTION_HEADER::Characteristics </summary>
///
/// <param name="dwProtection">
/// page protection constant
///
/// <returns>
/// Characteristics for use in section header </returns>
DWORD EXPORT LIBCALL MrPageToSectionProtection(IN const DWORD dwProtection) {
    DWORD dwChar = 0;
    if (dwProtection & PAGE_NOACCESS) // PAGE_NOACCESS
        return dwChar;
    if (dwProtection & PAGE_NOCACHE)
        dwChar |= IMAGE_SCN_MEM_NOT_CACHED;
    if (dwProtection & 0x70) // execute permissions on 2nd nibble
        dwChar |= IMAGE_SCN_MEM_EXECUTE;
    if (dwProtection & 0x44) // write permissions on 3rd bit of each nibble
        dwChar |= IMAGE_SCN_MEM_WRITE;
    if (dwProtection & 0x22) // read permissions on 2nd bit of each nibble
        dwChar |= IMAGE_SCN_MEM_READ;
  // other status flags
    if (dwChar & IMAGE_SCN_MEM_READ     // correct this
     && dwChar & IMAGE_SCN_MEM_EXECUTE)
        dwChar |= IMAGE_SCN_CNT_CODE;
    if (dwChar & IMAGE_SCN_MEM_READ     // we really need the pe headers to check if there will be unitialized data
     && dwChar & IMAGE_SCN_MEM_WRITE)   // (padding at end of section), however it's usually safe to assume there is
        dwChar |= IMAGE_SCN_CNT_INITIALIZED_DATA;
    return dwChar;
}