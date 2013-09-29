#include "..\..\doc\PEel_public.h"

#include "..\test\test.h"

#include <stdlib.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    VIRTUAL_MODULE32 vm = {0};

    {
        RAW_PE32 rpe = {0};
        if (!LOGICAL_SUCCESS(PlAttachFile32(test_exe, &rpe)))
            return 0;
        printf("File aligned PE at %08p", rpe.pDosHdr);
        if (!LOGICAL_SUCCESS(PlFileToImage32(&rpe, &vm))) {
            PlDetachFile32(&rpe);
            return 0;
        }
        PlDetachFile32(&rpe);
    }
    printf("\nImage aligned PE at %08p", vm.pBaseAddr);
    // 1. Relocate (we know our image has a .reloc section)
    if ((void*)vm.PE.pNtHdr->OptionalHeader.ImageBase != vm.pBaseAddr) {
        PlRelocate32(&vm.PE, vm.PE.pNtHdr->OptionalHeader.ImageBase, (PTR32)vm.pBaseAddr);
        printf("\nPE typically at %08p was relocated to %08p", vm.PE.pNtHdr->OptionalHeader.ImageBase, vm.pBaseAddr);
    }
    // 2. Import (yeah i know this is a terrible way, but I'm lazy and this is only an example)
    PlEnumerateImports32(&vm.PE);
    for (IMPORT_LIBRARY32* pIL = vm.PE.pImport; pIL != NULL; pIL = (IMPORT_LIBRARY32*)pIL->Flink) {
        printf("\nLoading library %s", pIL->Library);
        if (GetModuleHandleA(pIL->Library) == NULL) 
            LoadLibraryA(pIL->Library);
        for (IMPORT_ITEM32* pII = pIL->iiImportList; pII != NULL; pII = (IMPORT_ITEM32*)pII->Flink) {
            if (pII->Name == NULL && pII->Ordinal == NULL)
                break;
            if (pII->Name != NULL)
                printf("\n\tImporting %s", pII->Name);
            else
                printf("\n\tImporting ordinal %08lx", pII->Ordinal);
            *pII->dwItemPtr = (PTR32)GetProcAddress(GetModuleHandleA(pIL->Library), pII->Name != NULL ? pII->Name : pII->Ordinal);
        }
    }
    // 3. Protect
    PlProtectImage32(&vm);
    printf("\nApplied protection to image!");
    
    {
        PTR dwEntryPoint = vm.PE.pNtHdr->OptionalHeader.AddressOfEntryPoint + (PTR)vm.pBaseAddr;
        typedef void (*EntryPtr)();
        EntryPtr E = (EntryPtr)dwEntryPoint;
        if (dwEntryPoint) {
            printf("\nCalling entry point at %08p", dwEntryPoint);
            E();
        } else
            printf("\nImage does not have an entry point...");

    }
    printf("\nIf we reached here then our loaded file did not call exit()");
    for (IMPORT_LIBRARY32* pIL = vm.PE.pImport; pIL != NULL; pIL = (IMPORT_LIBRARY32*)pIL->Flink) {
        if (GetModuleHandleA(pIL->Library) != NULL) 
            FreeLibrary(GetModuleHandleA(pIL->Library));
    }
    printf("\nUnprotecting image!");
    PlUnprotectImage32(&vm);
    PlFreeEnumeratedImports32(&vm.PE);
    PlFreeImage32(&vm);
    printf("\nWe're done!");
    return 0;
}