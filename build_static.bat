:: Windows build script for PEel
:: x8esix

@echo off

:: gcc appears to produce MUCH smaller builds (20kb vs 175 kb)
:: plus no paths!

set sources=
set objects=

:: cleanup     
     FOR %%i in (*.o) DO del %%i
     IF EXIST ..\Release\PEel.lib del ..\Release\PEel.lib /Q

cd .\peel\

     FOR %%i in (*.c) DO (call :concat %%i & gcc -c %%i -std=c99 -Os -s -pedantic & ECHO Compiling %%i)
     ECHO.
     ECHO Linking library...
     ECHO.
     FOR %%i in (*.o) DO (call :concat2 %%i & ECHO Adding %%i to library)

     ar rcs ..\Release\PEel.lib %objects%

ECHO.
ECHO Cleaning up...
ECHO.
    
     FOR %%i in (*.o) DO (del %%i & ECHO Deleting %%i...)

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