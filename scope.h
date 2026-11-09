// scope.h -- shared "scope" logic for diag.dll / uxdiag.exe / scope_test.exe
//
// A scope is a comma-separated list of image file names, read from the
// "scope=" key in diag.conf. When non-empty it restricts which processes
// may create/rotate/append the hook log. Matching rules:
//   * empty or entry-less list (key absent, blank, ",,") -> no restriction
//   * case-insensitive exact match on the image file name (no wildcards)
//   * any directory part in an entry is stripped, so "svchost.exe" and
//     "C:\Windows\System32\svchost.exe" both match svchost.exe
//   * whitespace around entries is ignored; empty entries are skipped

#pragma once

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>  // wcstok_s

#define SCOPE_LIST_MAX 2048  // max length of the scope list (wide chars)

// Returns TRUE if exeBaseName (the running process' image file name, no path)
// is allowed to log under the given scope list.
static inline BOOL ScopeMatches(const WCHAR* exeBaseName, const WCHAR* scopeList)
{
    if (!scopeList || scopeList[0] == L'\0')
        return TRUE;  // not configured -> no restriction

    if (!exeBaseName || exeBaseName[0] == L'\0')
        return FALSE;

    WCHAR list[SCOPE_LIST_MAX];
    wcsncpy_s(list, sizeof(list) / sizeof(list[0]), scopeList, _TRUNCATE);

    BOOL sawEntry = FALSE;
    WCHAR* save = NULL;
    for (WCHAR* entry = wcstok_s(list, L",", &save); entry; entry = wcstok_s(NULL, L",", &save))
    {
        while (*entry == L' ' || *entry == L'\t')
            entry++;
        if (*entry == L'\0')
            continue;  // empty entry (e.g. ",," or a trailing comma)

        sawEntry = TRUE;

        // Strip trailing whitespace ("a.exe , b.exe" style values).
        size_t len = wcslen(entry);
        while (len > 0 && (entry[len - 1] == L' ' || entry[len - 1] == L'\t'))
            entry[--len] = L'\0';

        // Strip any directory part from the configured entry.
        WCHAR* slash = wcsrchr(entry, L'\\');
        if (slash)
            memmove(entry, slash + 1, (wcslen(slash + 1) + 1) * sizeof(WCHAR));

        if (lstrcmpiW(entry, exeBaseName) == 0)
            return TRUE;
    }

    // A list with no valid entries behaves like an empty scope.
    return !sawEntry;
}

// Number of non-empty entries in a scope list (0 for empty/entry-less lists).
static inline int ScopeCountEntries(const WCHAR* scopeList)
{
    if (!scopeList || scopeList[0] == L'\0')
        return 0;

    WCHAR list[SCOPE_LIST_MAX];
    wcsncpy_s(list, sizeof(list) / sizeof(list[0]), scopeList, _TRUNCATE);

    int count = 0;
    WCHAR* save = NULL;
    for (WCHAR* entry = wcstok_s(list, L",", &save); entry; entry = wcstok_s(NULL, L",", &save))
    {
        while (*entry == L' ' || *entry == L'\t')
            entry++;
        if (*entry != L'\0')
            count++;
    }
    return count;
}
