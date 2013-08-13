include 'win32a.inc'

format PE gui 6.0 NX at 0x000400000
entry main

section '.text' code readable executable
main:
	xor eax, eax
	invoke MessageBoxA,eax,szText,szTitle,MB_OK

section '.data' data readable writeable
szText db 'hello',0
szTitle db 'world',0


section '.idata' import data readable writeable
library kernel32,'kernel32.dll',\
	user32,'user32.dll'

import kernel32,\
       ExitProcess,'ExitProcess'

import user32,\
       MessageBoxA,'MessageBoxA'