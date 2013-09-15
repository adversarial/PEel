:: Windows build script for PEel shared library
:: x8esix

@echo off

:: Constructs resource file for PEel.so
:: Windows 7A Sdk and MSVS 2010 required


set PATH=%PATH%;C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\Bin;C:\Program Files\Microsoft Visual Studio 10.0\VC\Bin;C:\Program Files\Microsoft Visual Studio 10.0\Common7\ID

set INCLUDE=%INCLUDE%;C:\Program Files\Microsoft SDKs\Windows\v7.0A\Include;C:\Program Files\Microsoft Visual Studio 10.0\VC\include;C:\Program Files\Microsoft Visual Studio 10.0\VC\atlmfc\include

set LIB=%LIB%;C:\Program Files\Microsoft SDKs\Windows\v7.0A\Lib;C:\Program Files\Microsoft Visual Studio 10.0\VC\lib;

set sources=
set objects=

:: cleanup     
     FOR %%i in (*.o) DO del %%i
     IF EXIST ..\Release\PEel.lib del ..\Release\PEel.lib /Q
     IF EXIST peel.res del peel.res /Q

cd .\peel\

     FOR %%i in (*.c) DO (call :concat %%i & gcc -c -DBUILDING_EXAMPLE_DLL %%i -std=c99 -O2 -pedantic & ECHO Compiling %%i)
     ECHO.
     ECHO Linking library...
     ECHO.
     FOR %%i in (*.o) DO (call :concat2 %%i & ECHO Adding %%i to library)

     ECHO Compiling resource file...
     windres peel.rc -O coff -o peel.res
:: Icon makes hugeass library tho :\
::     call :concat2 peel.res

     gcc -shared -o ..\Release\PEel.dll %objects% -Wl,--out-implib,..\Release\PEel_dll.lib

ECHO.
ECHO Cleaning up...
ECHO.
    
     FOR %%i in (*.o) DO (del %%i & ECHO Deleting %%i...)
     del peel.res /Q

ECHO.
ECHO Compilation complete!
ECHO.
pause

:concat
set sources=%sources% %1
goto :eof

:concat2:
set objects=%objects% %1
goto :eof