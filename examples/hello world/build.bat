:: build script for hello world PE loader

gcc -c -masm=intel helloworld.c -std=c99 -static -O2
gcc -o helloworld.exe helloworld.o ..\..\Release\PEel.lib
del helloworld.o