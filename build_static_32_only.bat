:: Windows build script for PEel
:: x8esix

@echo off

:: gcc appears to produce MUCH smaller builds (20kb vs 175 kb)
:: plus no paths!

set objects=

:: cleanup     
     FOR %%i in (*.o) DO del %%i
     IF EXIST ..\Release\PEel32.lib del ..\Release\PEel32.lib /Q

cd .\peel\
     FOR %%i in (*.c) DO (gcc -c %%i -std=c99 -Os -s -DSUPPORT_PE32PLUS=0 -DSUPPORT_PE32=1 & ECHO Compiling %%i)

     ECHO.
     ECHO Linking library...
     ECHO.
     FOR %%i in (*.o) DO (call :concat %%i & ECHO Adding %%i to library)

     ar rcs ..\Release\PEel32.lib %objects%
ECHO.
ECHO Cleaning up...
ECHO.
    
 ::    FOR %%i in (*.o) DO (del %%i & ECHO Deleting %%i...)

ECHO.
ECHO Compilation complete!
ECHO.
pause

:concat:
set objects=%objects% %1
goto :eof