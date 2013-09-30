@echo off

set objects=

:: cleanup     
     FOR %%i in (*.o) DO del %%i
     IF EXIST ..\Release\PEel64.dll del ..\Release\PEel64.dll /Q

cd .\peel\

     FOR %%i in (*.c) DO (gcc -c -DBUILDING_EXAMPLE_DLL -DSUPPORT_PE32PLUS %%i -std=c99 -Os & ECHO Compiling %%i)

     ECHO.
     ECHO Linking library...
     ECHO.

     FOR %%i in (*.o) DO (call :concat2 %%i & ECHO Adding %%i to library)    

     dllwrap --def ..\doc\PEel64.def -o ..\Release\PEel64.dll %objects%

  ::   gcc -shared -o ..\Release\PEel.dll %objects% -Wl,--kill-at,--output-def,..\doc\PEel64.def

ECHO.
ECHO Cleaning up...
ECHO.
    
     FOR %%i in (*.o) DO (del %%i & ECHO Deleting %%i...)

ECHO.
ECHO Compilation complete!
ECHO.
pause

:concat2:
set objects=%objects% %1
goto :eof