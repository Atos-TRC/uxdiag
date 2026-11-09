// scope_test.exe -- verifies the extended "scope" feature of diag.dll WITHOUT
// calling RegisterUserApiHook (which requires SYSTEM).
//
// Part 1: unit tests for ScopeMatches()/ScopeCountEntries() from scope.h --
//         the exact code diag.dll compiles in, exercised with a table of
//         image names and scope lists.
//
// Part 2: integration tests that load the real diag.dll (copied to a temp dir
//         next to a generated diag.conf) and invoke its exported StartLog
//         entry point directly -- exactly what win32k would do once the hook
//         is registered. For each scope configuration we check whether the
//         DLL created/appended/rotated the log or stayed silent. Loading a
//         DLL in-process needs no privileges.
//
// Build (or just run build.bat):
//   rc /nologo /fo scope_test.res scope_test.rc
//   cl /nologo /W3 /EHsc scope_test.cpp /Fe:scope_test.exe /link /MACHINE:X64 scope_test.res

#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "scope.h"

#pragma comment(lib, "user32.lib")

static int g_pass = 0;
static int g_fail = 0;

static void Check(const char* label, BOOL ok)
{
    if (ok)
    {
        g_pass++;
        wprintf(L"[PASS] %hs\n", label);
    }
    else
    {
        g_fail++;
        wprintf(L"[FAIL] %hs\n", label);
    }
}

// ---------------------------------------------------------------- part 1 --

static void TestMatch(const char* exe, const char* scope, BOOL expect)
{
    WCHAR we[256] = {};
    WCHAR ws[4096] = {};
    if (exe)
        MultiByteToWideChar(CP_UTF8, 0, exe, -1, we, sizeof(we) / sizeof(WCHAR));
    if (scope)
        MultiByteToWideChar(CP_UTF8, 0, scope, -1, ws, sizeof(ws) / sizeof(WCHAR));

    char label[512];
    sprintf_s(label, "ScopeMatches(exe=%s, scope=%s) == %d",
              exe ? exe : "(null)", scope ? scope : "(null)", expect);
    Check(label, ScopeMatches(exe ? we : NULL, scope ? ws : NULL) == expect);
}

static void TestCount(const char* scope, int expect)
{
    WCHAR ws[4096] = {};
    if (scope)
        MultiByteToWideChar(CP_UTF8, 0, scope, -1, ws, sizeof(ws) / sizeof(WCHAR));

    char label[512];
    sprintf_s(label, "ScopeCountEntries(%s) == %d", scope ? scope : "(null)", expect);
    Check(label, ScopeCountEntries(scope ? ws : NULL) == expect);
}

static void UnitTests()
{
    wprintf(L"\n=== Part 1: scope.h unit tests ===\n");

    // -- empty / absent / entry-less lists -> unrestricted -----------------
    TestMatch("svchost.exe", "", TRUE);
    TestMatch("svchost.exe", NULL, TRUE);
    TestMatch("svchost.exe", "   ", TRUE);
    TestMatch("svchost.exe", ",,,", TRUE);

    // -- single name (previous behavior) -----------------------------------
    TestMatch("svchost.exe", "svchost.exe", TRUE);
    TestMatch("svchost.exe", "notepad.exe", FALSE);
    TestMatch("SVCHOST.EXE", "svchost.exe", TRUE);   // case-insensitive, exe side
    TestMatch("svchost.exe", "SvChOsT.Exe", TRUE);   // case-insensitive, entry side

    // -- multiple names (new behavior) --------------------------------------
    TestMatch("notepad.exe", "svchost.exe,notepad.exe", TRUE);  // match in list
    TestMatch("winlogon.exe", "svchost.exe,notepad.exe", FALSE); // no match in list
    TestMatch("svchost.exe", ", ,svchost.exe,", TRUE);          // empty entries skipped
    TestMatch("a.exe", "ab.exe", FALSE);                        // no prefix matching
    TestMatch("svchost.exe", "svchost.exe*", FALSE);            // no wildcards
    TestMatch(NULL, "svchost.exe", FALSE);                      // no exe name -> cannot match

    // -- path stripping in entries ------------------------------------------
    TestMatch("svchost.exe", "C:\\Windows\\System32\\svchost.exe", TRUE);
    TestMatch("svchost.exe", "C:\\x\\notepad.exe, C:\\y\\svchost.exe ", TRUE);

    wprintf(L"\n--- ScopeCountEntries() ---\n");
    TestCount("", 0);
    TestCount(NULL, 0);
    TestCount("   ", 0);
    TestCount(",,,", 0);
    TestCount("a.exe", 1);
    TestCount("a.exe,b.exe", 2);
    TestCount(" , a.exe ,,b.exe, ", 2);
}

// ---------------------------------------------------------------- part 2 --

static WCHAR g_root[MAX_PATH];   // <temp>\uxdiag_scope_test
static WCHAR g_dllDir[MAX_PATH]; // g_root\dll  (diag.dll + diag.conf)
static WCHAR g_logDir[MAX_PATH]; // g_root\log  (DIAG.log, rotate-*.log)
static HMODULE g_hDll = NULL;

static void Die(const char* what)
{
    wprintf(L"[!] %hs failed (error %lu)\n", what, GetLastError());
    exit(2);
}

// Recursively delete a directory tree (including the directory itself).
static BOOL DeleteTree(WCHAR* path)
{
    WCHAR spec[MAX_PATH];
    _snwprintf_s(spec, _TRUNCATE, L"%s\\*", path);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(spec, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;

    BOOL ok = TRUE;
    do
    {
        if (lstrcmpiW(fd.cFileName, L".") == 0 || lstrcmpiW(fd.cFileName, L"..") == 0)
            continue;

        WCHAR child[MAX_PATH];
        _snwprintf_s(child, _TRUNCATE, L"%s\\%s", path, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (!DeleteTree(child))
                ok = FALSE;
        }
        else if (!DeleteFileW(child))
        {
            ok = FALSE;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    return RemoveDirectoryW(path);
}

static void SetupDirs()
{
    WCHAR temp[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp))
        Die("GetTempPathW");

    _snwprintf_s(g_root, _TRUNCATE, L"%suxdiag_scope_test", temp);
    _snwprintf_s(g_dllDir, _TRUNCATE, L"%s\\dll", g_root);
    _snwprintf_s(g_logDir, _TRUNCATE, L"%s\\log", g_root);

    // Start from a clean slate (leftovers from a crashed previous run).
    DeleteTree(g_root);

    if (!CreateDirectoryW(g_root, NULL)) Die("CreateDirectory root");
    if (!CreateDirectoryW(g_dllDir, NULL)) Die("CreateDirectory dll dir");
    if (!CreateDirectoryW(g_logDir, NULL)) Die("CreateDirectory log dir");

    // Copy diag.dll into the temp dir so its DllMain reads OUR generated conf.
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    WCHAR* slash = wcsrchr(exePath, L'\\');
    if (slash)
        *slash = L'\0';

    WCHAR srcDll[MAX_PATH], dstDll[MAX_PATH];
    _snwprintf_s(srcDll, _TRUNCATE, L"%s\\diag.dll", exePath);
    _snwprintf_s(dstDll, _TRUNCATE, L"%s\\diag.dll", g_dllDir);
    if (GetFileAttributesW(srcDll) == INVALID_FILE_ATTRIBUTES)
        Die("diag.dll not found next to scope_test.exe");
    if (!CopyFileW(srcDll, dstDll, FALSE))
        Die("CopyFileW diag.dll");

    wprintf(L"[*] work dir: %s\n", g_root);
}

// Write the generated diag.conf. scopeValue == NULL omits the key entirely
// (tests the "key absent" path); "" writes an empty value.
static void WriteConf(const WCHAR* scopeValue, int logrotate)
{
    char logDirUtf8[MAX_PATH * 2] = {};
    WideCharToMultiByte(CP_UTF8, 0, g_logDir, -1, logDirUtf8, sizeof(logDirUtf8), NULL, NULL);
    char scopeUtf8[4096] = "";
    if (scopeValue)
        WideCharToMultiByte(CP_UTF8, 0, scopeValue, -1, scopeUtf8, sizeof(scopeUtf8), NULL, NULL);

    char conf[8192];
    if (scopeValue)
        sprintf_s(conf, "logdir=%s\nlogname=DIAG.log\nlogrotate=%d\nscope=%s\n",
                  logDirUtf8, logrotate, scopeUtf8);
    else
        sprintf_s(conf, "logdir=%s\nlogname=DIAG.log\nlogrotate=%d\n",
                  logDirUtf8, logrotate);

    WCHAR confPath[MAX_PATH];
    _snwprintf_s(confPath, _TRUNCATE, L"%s\\diag.conf", g_dllDir);
    HANDLE h = CreateFileW(confPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        Die("CreateFileW diag.conf");
    DWORD written;
    WriteFile(h, conf, (DWORD)strlen(conf), &written, NULL);
    CloseHandle(h);
}

static void CleanLogDir()
{
    WCHAR spec[MAX_PATH];
    _snwprintf_s(spec, _TRUNCATE, L"%s\\*", g_logDir);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(spec, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;
    do
    {
        if (lstrcmpiW(fd.cFileName, L".") == 0 || lstrcmpiW(fd.cFileName, L"..") == 0)
            continue;
        WCHAR child[MAX_PATH];
        _snwprintf_s(child, _TRUNCATE, L"%s\\%s", g_logDir, fd.cFileName);
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            DeleteFileW(child);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static BOOL FileExists(const WCHAR* path)
{
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

// Read a whole file (as bytes) into buf; returns byte count or -1.
static int ReadFileAll(const WCHAR* path, char* buf, size_t bufLen)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    DWORD n = 0;
    ReadFile(h, buf, (DWORD)(bufLen - 1), &n, NULL);
    CloseHandle(h);
    buf[n] = '\0';
    return (int)n;
}

typedef BOOL (WINAPI *PFN_StartLog)(ULONG, void*);

// Load the temp-dir diag.dll, call its exported StartLog(0, NULL) -- exactly
// what win32k does for a window-creating process once the hook is registered --
// then verify whether the log was written or not.
static void RunCase(const char* label, const WCHAR* scopeValue, int logrotate, BOOL expectLogging)
{
    if (g_hDll)
    {
        FreeLibrary(g_hDll);
        g_hDll = NULL;
    }
    CleanLogDir();
    WriteConf(scopeValue, logrotate);

    WCHAR dllPath[MAX_PATH];
    _snwprintf_s(dllPath, _TRUNCATE, L"%s\\diag.dll", g_dllDir);

    g_hDll = LoadLibraryW(dllPath);
    if (!g_hDll)
    {
        Check(label, FALSE);
        wprintf(L"       [!] LoadLibraryW failed (%lu)\n", GetLastError());
        return;
    }

    PFN_StartLog pfnStartLog = (PFN_StartLog)(DWORD_PTR)GetProcAddress(g_hDll, "StartLog");
    if (!pfnStartLog)
    {
        Check(label, FALSE);
        wprintf(L"       [!] GetProcAddress(StartLog) failed\n");
        FreeLibrary(g_hDll);
        g_hDll = NULL;
        return;
    }

    pfnStartLog(0, NULL);

    WCHAR logPath[MAX_PATH];
    _snwprintf_s(logPath, _TRUNCATE, L"%s\\DIAG.log", g_logDir);

    BOOL sawLog = FileExists(logPath);
    if (expectLogging)
    {
        if (!sawLog)
        {
            Check(label, FALSE);
            wprintf(L"       [!] expected %s but it was not created\n", logPath);
        }
        else
        {
            char buf[8192];
            int n = ReadFileAll(logPath, buf, sizeof(buf));
            BOOL hasInit  = (n > 0) && strstr(buf, "[DIAG] diag is running") != NULL;
            BOOL hasStart = (n > 0) && strstr(buf, "StartLog(init)") != NULL;
            Check(label, hasInit && hasStart);
            if (!hasInit || !hasStart)
                wprintf(L"       [!] log missing markers: DllMain=%d StartLog=%d\n", hasInit, hasStart);
        }
    }
    else
    {
        Check(label, !sawLog);
        if (sawLog)
        {
            char buf[512];
            int n = ReadFileAll(logPath, buf, sizeof(buf));
            wprintf(L"       [!] out-of-scope process wrote %d bytes to the log:\n%hs\n",
                    n > 0 ? n : 0, n > 0 ? buf : "(empty)");
        }
    }

    FreeLibrary(g_hDll);
    g_hDll = NULL;
}

// Rotation is gated by the same scope check: in-scope processes must rename the
// existing log to rotate-NNNNN.log and start a fresh one; out-of-scope ones
// must leave the file byte-for-byte untouched.
static void RunRotateCase(const char* label, const WCHAR* scopeValue, BOOL inScope)
{
    if (g_hDll)
    {
        FreeLibrary(g_hDll);
        g_hDll = NULL;
    }
    CleanLogDir();

    // Pre-create the log with a sentinel.
    WCHAR logPath[MAX_PATH];
    _snwprintf_s(logPath, _TRUNCATE, L"%s\\DIAG.log", g_logDir);
    const char sentinel[] = "SENTINEL-OLD-LOG\r\n";
    HANDLE h = CreateFileW(logPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        Die("CreateFileW pre-existing DIAG.log");
    DWORD written;
    WriteFile(h, sentinel, (DWORD)(sizeof(sentinel) - 1), &written, NULL);
    CloseHandle(h);

    WriteConf(scopeValue, /*logrotate=*/1);

    WCHAR dllPath[MAX_PATH];
    _snwprintf_s(dllPath, _TRUNCATE, L"%s\\diag.dll", g_dllDir);
    g_hDll = LoadLibraryW(dllPath);
    if (!g_hDll)
    {
        Check(label, FALSE);
        wprintf(L"       [!] LoadLibraryW failed (%lu)\n", GetLastError());
        return;
    }

    PFN_StartLog pfnStartLog = (PFN_StartLog)(DWORD_PTR)GetProcAddress(g_hDll, "StartLog");
    if (!pfnStartLog)
    {
        Check(label, FALSE);
        wprintf(L"       [!] GetProcAddress(StartLog) failed\n");
        FreeLibrary(g_hDll);
        g_hDll = NULL;
        return;
    }

    pfnStartLog(0, NULL);

    BOOL ok = FALSE;
    if (inScope)
    {
        // New DIAG.log with our markers AND the old log renamed to rotate-*.log
        // keeping the sentinel.
        char buf[8192];
        int n = ReadFileAll(logPath, buf, sizeof(buf));
        if (n > 0 && strstr(buf, "[DIAG] diag is running") && strstr(buf, "StartLog(init)"))
        {
            WCHAR spec[MAX_PATH];
            _snwprintf_s(spec, _TRUNCATE, L"%s\\rotate-*", g_logDir);
            WIN32_FIND_DATAW fd;
            HANDLE fh = FindFirstFileW(spec, &fd);
            if (fh != INVALID_HANDLE_VALUE)
            {
                WCHAR rotPath[MAX_PATH];
                _snwprintf_s(rotPath, _TRUNCATE, L"%s\\%s", g_logDir, fd.cFileName);
                char rbuf[256];
                if (ReadFileAll(rotPath, rbuf, sizeof(rbuf)) > 0 && strstr(rbuf, "SENTINEL-OLD-LOG"))
                    ok = TRUE;
                FindClose(fh);
            }
        }
        if (!ok)
            wprintf(L"       [!] expected rotation: new log and/or rotate-* with sentinel missing\n");
    }
    else
    {
        // File must be byte-for-byte the sentinel, and no rotate-* file may exist.
        char buf[256];
        int n = ReadFileAll(logPath, buf, sizeof(buf));
        BOOL untouched = (n == (int)(sizeof(sentinel) - 1)) && strncmp(buf, sentinel, n) == 0;

        WCHAR spec[MAX_PATH];
        _snwprintf_s(spec, _TRUNCATE, L"%s\\rotate-*", g_logDir);
        WIN32_FIND_DATAW fd;
        HANDLE fh = FindFirstFileW(spec, &fd);
        BOOL noRotate = (fh == INVALID_HANDLE_VALUE);
        if (fh != INVALID_HANDLE_VALUE)
            FindClose(fh);

        ok = untouched && noRotate;
        if (!ok)
            wprintf(L"       [!] out-of-scope rotation case: untouched=%d noRotate=%d\n", untouched, noRotate);
    }

    Check(label, ok);

    FreeLibrary(g_hDll);
    g_hDll = NULL;
}

static void IntegrationTests()
{
    wprintf(L"\n=== Part 2: diag.dll integration tests (no user32 routine involved) ===\n");
    SetupDirs();

    // Image name of THIS process -- what diag.dll sees via GetModuleFileNameW(NULL).
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    const WCHAR* me = wcsrchr(exePath, L'\\');
    if (me)
        me++;
    else
        me = exePath;
    wprintf(L"[*] test process image: %s\n", me);

    WCHAR scopeBuf[4096];

    // -- logging gate --------------------------------------------------------
    RunCase("empty scope -> all processes log", L"", 0, TRUE);
    RunCase("scope key absent -> all processes log", NULL, 0, TRUE);
    RunCase("single non-matching name -> silent", L"definitely_not_me.exe", 0, FALSE);

    _snwprintf_s(scopeBuf, _TRUNCATE, L"other1.exe,%s,other2.exe", me);
    RunCase("multi-name list, match in middle -> logs", scopeBuf, 0, TRUE);

    _snwprintf_s(scopeBuf, _TRUNCATE, L"%s,other.exe", me);
    RunCase("multi-name list, match first -> logs", scopeBuf, 0, TRUE);

    _snwprintf_s(scopeBuf, _TRUNCATE, L"other.exe,nomatch.exe");
    RunCase("multi-name list, no match -> silent", scopeBuf, 0, FALSE);

    _snwprintf_s(scopeBuf, _TRUNCATE, L"C:\\Windows\\System32\\%s", me);
    RunCase("path-form entry -> stripped and matches", scopeBuf, 0, TRUE);

    WCHAR upper[256];
    wcscpy_s(upper, sizeof(upper) / sizeof(WCHAR), me);
    CharUpperW(upper);
    RunCase("case-insensitive entry -> matches", upper, 0, TRUE);

    _snwprintf_s(scopeBuf, _TRUNCATE, L"  ,  %s  ,", me);
    RunCase("whitespace-padded entries -> trimmed and match", scopeBuf, 0, TRUE);

    // -- rotation gate -------------------------------------------------------
    _snwprintf_s(scopeBuf, _TRUNCATE, L"%s", me);
    RunRotateCase("rotation: in-scope process rotates and logs", scopeBuf, TRUE);
    RunRotateCase("rotation: out-of-scope process leaves log untouched", L"nomatch.exe", FALSE);

    // -- cleanup ---------------------------------------------------------------
    if (g_hDll)
    {
        FreeLibrary(g_hDll);
        g_hDll = NULL;
    }
    DeleteTree(g_root);
}

int wmain()
{
    UnitTests();
    IntegrationTests();

    wprintf(L"\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
