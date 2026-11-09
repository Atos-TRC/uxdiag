// This is a demo of RegisterUserApiHook, disguised as a diagnostic loggic tool.
// RegisterUserApiHook requires NT AUTHORITY/SYSTEM unrestrcited token and SeTcbPrivilege enabled.

// Whenever the diag.dll gets injected into a new process in Session 0, its PID and command line are
// logged in the log file (configurable).
// If combined with the logrotate option, this can be used to move artbirary files.
// Which becomes helpful at evaluating tamper-protect logic of individual security products.

// Author: Julian Horoszkiewicz (Atos Threat Research Center)

// Build (or just run build.bat):
// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// rc.exe /nologo /fo diag.res diag.rc
// cl.exe /nologo /LD /W3 /EHsc diag.cpp /Fe:diag.dll /link /DEF:diag.def /MACHINE:X64 diag.res

#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "scope.h"

#pragma comment(lib, "user32.lib")

static WCHAR g_logDir[MAX_PATH] = L"C:\\Users\\Public";
static WCHAR g_logName[MAX_PATH] = L"DIAG.log";
static BOOL g_logRotate = FALSE;
static WCHAR g_scope[SCOPE_LIST_MAX] = {};  // comma-separated list; empty -> no restriction (all processes)

// Reads <confName> from the directory containing this DLL and looks up a
// "key=value" entry. Blank lines and '#' comments are ignored, whitespace
// around keys and values is trimmed, key match is case-insensitive.
// Returns TRUE if the key was found.
static BOOL ReadConfValue(HMODULE hModule, const WCHAR* confName, const char* key, WCHAR* out, int outChars)
{
    WCHAR confPath[MAX_PATH];
    GetModuleFileNameW(hModule, confPath, MAX_PATH);
    WCHAR* slash = wcsrchr(confPath, L'\\');
    if (slash)
        wcscpy_s(slash + 1, MAX_PATH - (slash + 1 - confPath), confName);
    else
        return FALSE;

    HANDLE hFile = CreateFileW(confPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    char buf[4096] = {};
    DWORD bytesRead = 0;
    ReadFile(hFile, buf, sizeof(buf) - 1, &bytesRead, NULL);
    CloseHandle(hFile);

    char* save = NULL;
    for (char* line = strtok_s(buf, "\n", &save); line; line = strtok_s(NULL, "\n", &save))
    {
        while (*line == ' ' || *line == '\t' || *line == '\r')
            line++;
        if (*line == '\0' || *line == '#')
            continue;

        char* eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = '\0';

        char* kEnd = eq;
        while (kEnd > line && (kEnd[-1] == ' ' || kEnd[-1] == '\t'))
            *--kEnd = '\0';

        if (_stricmp(line, key) != 0)
            continue;

        char* val = eq + 1;
        while (*val == ' ' || *val == '\t')
            val++;
        size_t vLen = strlen(val);
        while (vLen > 0 && (val[vLen - 1] == ' ' || val[vLen - 1] == '\t' || val[vLen - 1] == '\r'))
            val[--vLen] = '\0';

        MultiByteToWideChar(CP_UTF8, 0, val, -1, out, outChars);
        return TRUE;
    }
    return FALSE;
}

static void LogMessage(const char* msg)
{
    OutputDebugStringA(msg);

    WCHAR path[MAX_PATH];
    _snwprintf_s(path, _TRUNCATE, L"%s\\%s", g_logDir, g_logName);

    HANDLE hFile = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD written;
        WriteFile(hFile, msg, (DWORD)strlen(msg), &written, NULL);
        CloseHandle(hFile);
    }
}

// 5 random digits for the rotated log file name. Uses RtlGenRandom so that
// every process gets different digits (rand() would share one seed per process).
static DWORD RandomDigits()
{
    typedef BOOL (WINAPI *PFN_SystemFunction036)(PVOID, ULONG);
    static PFN_SystemFunction036 pfnRtlGenRandom = NULL;
    if (!pfnRtlGenRandom)
        pfnRtlGenRandom = (PFN_SystemFunction036)
            GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "SystemFunction036");

    DWORD v = 0;
    if (pfnRtlGenRandom)
        pfnRtlGenRandom(&v, sizeof(v));
    else
        v = GetTickCount() ^ (GetCurrentProcessId() << 16);

    return v % 100000;
}

// On each load: rename the current log file to "rotate-<5 digits><ext>", if any.
static void RotateLog()
{
    WCHAR curPath[MAX_PATH];
    _snwprintf_s(curPath, _TRUNCATE, L"%s\\%s", g_logDir, g_logName);

    if (GetFileAttributesW(curPath) == INVALID_FILE_ATTRIBUTES)
        return;  // no existing log -- nothing to rotate

    DWORD rnd = RandomDigits();
    WCHAR newPath[MAX_PATH];
    const WCHAR* ext = wcsrchr(g_logName, L'.');
    if (ext)
        _snwprintf_s(newPath, _TRUNCATE, L"%s\\rotate-%05lu%s", g_logDir, rnd, ext);
    else
        _snwprintf_s(newPath, _TRUNCATE, L"%s\\rotate-%05lu", g_logDir, rnd);

    if (!MoveFileW(curPath, newPath))
    {
        // Rotation failed (e.g. access denied) -- continue with normal logging
        char buf[256];
        sprintf_s(buf, "[DIAG] log rotation failed (error %lu) -- continuing with normal logging\r\n",
                  GetLastError());
        LogMessage(buf);
    }
}

// If a "scope" is configured, only processes whose image file name matches one
// of the comma-separated entries may rotate/create/append the log; every other
// process is ignored silently. An empty scope (key absent or blank) leaves
// behavior unchanged. See scope.h for the matching rules (case-insensitive,
// paths in entries are stripped, no wildcards).
static BOOL ScopeAllowsLogging()
{
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    const WCHAR* base = wcsrchr(exePath, L'\\');
    if (base)
        base++;
    else
        base = exePath;

    return ScopeMatches(base, g_scope);
}

extern "C" __declspec(dllexport)
BOOL WINAPI StartLog(ULONG dwState, void* pUserApiHook)
{
    // Out of scope -> return silently without touching the log.
    if (!ScopeAllowsLogging())
        return TRUE;

    if (dwState == 0)
    {
        char buf[256];
        sprintf_s(buf, "[DIAG] StartLog(init) in PID %lu\r\n",
                  GetCurrentProcessId());
        LogMessage(buf);
        return TRUE;
    }

    if (dwState == 1 || dwState == 2)
    {
        char buf[256];
        sprintf_s(buf, "[DIAG] StartLog(uninit=%lu) in PID %lu\r\n",
                  dwState, GetCurrentProcessId());
        LogMessage(buf);
    }

    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        ReadConfValue(hModule, L"diag.conf", "logdir", g_logDir, sizeof(g_logDir) / sizeof(WCHAR));
        ReadConfValue(hModule, L"diag.conf", "logname", g_logName, sizeof(g_logName) / sizeof(WCHAR));

        WCHAR rotBuf[MAX_PATH] = {};
        if (ReadConfValue(hModule, L"diag.conf", "logrotate", rotBuf, sizeof(rotBuf) / sizeof(WCHAR)) && wcscmp(rotBuf, L"0") != 0)
            g_logRotate = TRUE;

        ReadConfValue(hModule, L"diag.conf", "scope", g_scope, sizeof(g_scope) / sizeof(WCHAR));

        // Out of scope -> skip rotation and the initial log write entirely.
        if (!ScopeAllowsLogging())
            return TRUE;

        if (g_logRotate)
            RotateLog();

        char cmdLine[8192] = {0};
        const char* cl = GetCommandLineA();
        if (cl)
            strncpy_s(cmdLine, sizeof(cmdLine), cl, _TRUNCATE);
        char buf[sizeof(cmdLine) + MAX_PATH + 64];
        char exeName[MAX_PATH] = {0};
        GetModuleFileNameA(NULL, exeName, MAX_PATH);
        sprintf_s(buf, "[DIAG] diag is running. Current PID %lu (%s)\r\nCommand line: %s\r\n",
                  GetCurrentProcessId(), exeName, cmdLine);
        LogMessage(buf);
    }
    return TRUE;
}
