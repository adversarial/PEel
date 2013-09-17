:: build script for hello world PE loader

gcc -c helloworld.c -Os -s -std=c99
gcc -o helloworld.exe helloworld.o ..\..\Release\PEel.lib -Os -s
del helloworld.o