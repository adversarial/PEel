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
    LOGICAL CDECL PlDebugOut(IN const TCHAR* tzFormat, ...) {
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
PTR32 EXPORT LIBCALL PlAlignUp(IN const PTR offset, IN const PTR alignment) {
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
PTR32 EXPORT LIBCALL PlAlignDown(IN const PTR offset, IN const PTR alignment) {
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
DWORD EXPORT LIBCALL PlSectionToPageProtection(IN const DWORD dwCharacteristics) {
    DWORD dwProtect = dwCharacteristics;
    
    if (dwProtect & IMAGE_SCN_CNT_CODE)
        dwProtect |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    if (dwProtect & IMAGE_SCN_CNT_INITIALIZED_DATA
     || dwProtect & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
     dwProtect |= IMAGE_SCN_MEM_READ;
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
DWORD EXPORT LIBCALL PlPageToSectionProtection(IN const DWORD dwProtection) {
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