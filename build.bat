@echo off
setlocal

:: Find VS2022 vcvarsall.bat
set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "%VCVARS%" (
    echo [-] Could not find vcvarsall.bat
    exit /b 1
)

:: Set up x64 build environment
call "%VCVARS%" x64 >nul 2>&1

echo [*] Building diag.dll ...
rc /nologo /fo diag.res diag.rc
if errorlevel 1 (
    echo [-] Failed to compile diag.rc
    exit /b 1
)
cl /nologo /LD /W3 /EHsc diag.cpp /Fe:diag.dll /link /DEF:diag.def /MACHINE:X64 diag.res
if errorlevel 1 (
    echo [-] Failed to build diag.dll
    exit /b 1
)
echo [+] diag.dll built

echo [*] Building uxdiag.exe ...
rc /nologo /fo uxdiag.res uxdiag.rc
if errorlevel 1 (
    echo [-] Failed to compile uxdiag.rc
    exit /b 1
)
cl /nologo /W3 /EHsc uxdiag.cpp /Fe:uxdiag.exe /link /MACHINE:X64 shlwapi.lib advapi32.lib uxdiag.res
if errorlevel 1 (
    echo [-] Failed to build uxdiag.exe
    exit /b 1
)
echo [+] uxdiag.exe built

echo [*] Building scope_test.exe ...
rc /nologo /fo scope_test.res scope_test.rc
if errorlevel 1 (
    echo [-] Failed to compile scope_test.rc
    exit /b 1
)
cl /nologo /W3 /EHsc scope_test.cpp /Fe:scope_test.exe /link /MACHINE:X64 scope_test.res
if errorlevel 1 (
    echo [-] Failed to build scope_test.exe
    exit /b 1
)
echo [+] scope_test.exe built

echo.
echo === Build complete ===
echo.
echo Usage (from an elevated Admin/SYSTEM shell):
echo   2. uxdiag.exe [path\to\diag.dll]
echo      Logging is configured in diag.conf next to the hook DLL:
echo        logdir=C:\Users\Public
echo        logname=DIAG.log
echo        logrotate=0   (1 = rename current log to rotate-NNNNN.log on each load)
echo        scope=        (comma-separated image names, e.g. svchost.exe,notepad.exe; empty = all processes)
echo   3. Open any GUI app - check the hook log in the log dir above
echo.
echo Verify the scope logic without SYSTEM privileges (unit tests + real diag.dll load):
echo   scope_test.exe
echo.
