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

#include "kpeb.h"

void* EXPORT LIBCALL KpGetCurrentPeb() {
#   ifdef _WIN64
        return (void*)__readgsqword(0x60);
#   elif _WIN32
        return (void*)__readfsdword(0x30);
#   else
        return NULL;
#   endif
}

wchar_t* EXPORT LIBCALL KpGetEnvironmentVariable(IN const PEB* pPeb, IN const wchar_t* wzVar) {
	MEMORY_BASIC_INFORMATION mbi = {0};
  // there's no size variable for number of environment variables or space allocated
  // so we have to continue through each null terminated pair until we reach the end of the allocation
  // format: db 'Variable=Value',0,'Variable=Value',0
	wchar_t* wzInternal = *(wchar_t**)((PTR)pPeb->ProcessParameters + offsetof(PROCESS_PARAMETERS, Environment));
	VirtualQuery(wzInternal, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	do {
		if (!wcsnicmp(wzInternal, (wchar_t*)wzVar, wcslen((wchar_t*)wzVar))) {
			return wcschr(wzInternal, L'=') + 1;
		}
		wzInternal += wcslen(wzInternal) + 1;	// next var
	} while ((PTR)wzInternal < (PTR)mbi.BaseAddress + mbi.RegionSize);
	return NULL;
}

LDR_MODULE32* EXPORT LIBCALL KpGetLdrModule(IN const wchar_t* wzName) {
    LDR_MODULE32 *plmModule = NULL,
                 *plmModuleHeader = NULL;
    PEB          *pPeb = NULL;

    pPeb = (PEB*)KpGetCurrentPeb();
    if (pPeb == NULL)
        return NULL;
  // list is circular (last flink points to header)
    plmModule = (LDR_MODULE32*)pPeb->Ldr;
    plmModuleHeader = plmModule;
    do {
      // search for target module
        if (!wcsnicmp(wzName, plmModule->BaseDllName.Buffer, wcslen(wzName)))
            return plmModule;
        plmModule = (LDR_MODULE32*)plmModule->InMemoryOrderModuleList.Flink;
    } while (plmModule != plmModuleHeader);
    return NULL;
}