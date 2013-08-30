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
	wchar_t* wzInternal = *(wchar_t**)((DWORD_PTR)pPeb->ProcessParameters + offsetof(PROCESS_PARAMETERS, Environment));
	VirtualQuery(wzInternal, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	do {
		if (!wcsnicmp(wzInternal, (wchar_t*)wzVar, wcslen((wchar_t*)wzVar))) {
			return wcschr(wzInternal, L'=') + 1;
		}
		wzInternal = (wchar_t*)((DWORD_PTR)wzInternal + (((DWORD_PTR)wcslen(wzInternal) + 1) * sizeof(wchar_t)));	// next var
	} while ((DWORD_PTR)wzInternal < mbi.RegionSize + (DWORD_PTR)mbi.BaseAddress);
	return NULL;
}

LDR_MODULE32* EXPORT LIBCALL KpGetLdrModule(IN const wchar_t* wzName) {
    LDR_MODULE32 *plmModule = NULL,
                 *plmModuleHeader = NULL;
    PEB          *pPeb = NULL;

    pPeb = (PEB*)KpGetCurrentPeb();
    if (pPeb == NULL)
        return NULL;

    plmModule = (LDR_MODULE32*)pPeb->Ldr;
    plmModuleHeader = plmModule;
    do {
      // search for target module (either 8 or smaller name)
        if (!wcsnicmp(wzName, plmModule->BaseDllName.Buffer, wcslen(wzName)))
            return plmModule;
        plmModule = (LDR_MODULE32*)plmModule->InMemoryOrderModuleList.Flink;
    } while (plmModule != plmModuleHeader); // circular list
    return NULL;
}