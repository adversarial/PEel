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


#include <stdlib.h>
#include <stdio.h>

#include "..\test\test.h"
#include "..\..\doc\PEel_public.h"
#pragma comment (lib, "..\\..\\peel.lib")

#include <Windows.h>

int main(int argc, char* argv[]) {
    VIRTUAL_MODULE vm = {0};

    {
        RAW_PE rpe = {0};
        if (!LOGICAL_SUCCESS(PlAttachFile(test_exe, &rpe)))
            return 0;
        printf("File aligned PE at %p", rpe.pDosHdr);
        if (!LOGICAL_SUCCESS(PlFileToImage(&rpe, &vm))) {
            PlDetachFile(&rpe);
            return 0;
        }
        PlDetachFile(&rpe);
    }
    printf("\nImage aligned PE at %p", vm.pBaseAddr);
    // 1. Relocate (we know our image has a .reloc section)
    if ((void*)vm.PE.pNtHdr->OptionalHeader.ImageBase != vm.pBaseAddr) {
        PlRelocate(&vm.PE, vm.PE.pNtHdr->OptionalHeader.ImageBase, (PTR)vm.pBaseAddr);
        printf("\nPE typically at %p was relocated to %p", (void*)vm.PE.pNtHdr->OptionalHeader.ImageBase, vm.pBaseAddr);
    }
    // 2. Import (yeah i know this is a terrible way, but I'm lazy and this is only an example)
    PlEnumerateImports(&vm.PE);
    for (IMPORT_LIBRARY* pIL = vm.PE.pImport; pIL != NULL; pIL = (IMPORT_LIBRARY*)pIL->Flink) {
        printf("\nLoading library %s", pIL->Library);
        HMODULE hLib = LoadLibraryA(pIL->Library);
        for (IMPORT_ITEM* pII = pIL->iiImportList; pII != NULL; pII = (IMPORT_ITEM*)pII->Flink) {
            if (pII->Name == NULL && pII->Ordinal == NULL)
                break;
            if (pII->Name != NULL)
                printf("\n\tImporting %s", pII->Name);
            else
                printf("\n\tImporting ordinal %p", pII->Ordinal);
            *pII->dwItemPtr = (PTR)GetProcAddress(hLib, pII->Name != NULL ? pII->Name : pII->Ordinal);
        }
    }
    // 3. Protect
    PlProtectImage(&vm);
    printf("\nApplied protection to image!");
    
    {
        PTR dwEntryPoint = vm.PE.pNtHdr->OptionalHeader.AddressOfEntryPoint + (PTR)vm.pBaseAddr;
        typedef void (*EntryPtr)();
        EntryPtr E = (EntryPtr)dwEntryPoint;
        if (dwEntryPoint) {
            printf("\nCalling entry point at %p", (void*)dwEntryPoint);
            E();
        } else
            printf("\nImage does not have an entry point...");
    }

    printf("\nIf we reached here then our loaded file did not call exit()");
    for (IMPORT_LIBRARY* pIL = vm.PE.pImport; pIL != NULL; pIL = (IMPORT_LIBRARY*)pIL->Flink) {
        if (GetModuleHandleA(pIL->Library) != NULL) 
            FreeLibrary(GetModuleHandleA(pIL->Library));
    }
    printf("\nUnprotecting image!");
    PlUnprotectImage(&vm);
    PlFreeEnumeratedImports(&vm.PE);
    PlFreeImage(&vm);
    printf("\nWe're done!");
    return 0;
}
