#include <iostream>
#include <tchar.h>
#include <Windows.h>
#include <TlHelp32.h>


DWORD GetProcessId(const TCHAR* szProcessName)
{
    DWORD dwProcessId{ 0 };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(pe32);

        if (Process32First(hSnapshot, &pe32))
        {
            do
            {
                if (!_tcscmp(szProcessName, pe32.szExeFile))
                {
                    dwProcessId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    return dwProcessId;
}

HANDLE RunCreateProcess(wchar_t* szApplication)
{
    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi;

    if (CreateProcessW(nullptr, szApplication, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
    {
        _tprintf(_T("RunCreateProcess: %d\n"), pi.dwProcessId);;
        CloseHandle(pi.hThread);
    }

    return pi.hProcess;
}

HANDLE RunCreateProcessWithLogon(wchar_t* szApplication, const wchar_t* szUsername, const wchar_t* szDomain, const wchar_t* szPassword)
{
    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi;

    if (CreateProcessWithLogonW(szUsername, szDomain, szPassword, LOGON_WITH_PROFILE, nullptr, szApplication, 0, nullptr, nullptr, &si, &pi))
    {
        _tprintf(_T("RunCreateProcessWithLogon: %d\n"), pi.dwProcessId);
        CloseHandle(pi.hThread);
    }
    return pi.hProcess;
}

HANDLE RunCreateProcessWithToken(wchar_t* szApplication)
{
    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcessId(_T("explorer.exe")));
    HANDLE hToken = nullptr;
    if (OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken))
    {
        HANDLE hImpersonationToken = nullptr;
        if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenImpersonation, &hImpersonationToken))
        {
            if (CreateProcessWithTokenW(hImpersonationToken, 0, nullptr, szApplication, 0, nullptr, nullptr, &si, &pi))
            {
                _tprintf(_T("RunCreateProcessWithToken: %d\n"), pi.dwProcessId);
                CloseHandle(pi.hThread);
            }
            CloseHandle(hImpersonationToken);
        }
        CloseHandle(hToken);
    }

    return pi.hProcess;
}

int _tmain(int argc, const TCHAR* argv[], const TCHAR* env[])
{
    if (argc != 2)
    {
        _tprintf(_T("Usage: WindowsPrivilegeDeescalation.exe <application_path>\n"));
        return -1;
    }

    // Get Application Path
    constexpr size_t dwApplicationPathSize = 256;
    wchar_t szApplicationPath[dwApplicationPathSize];

#ifdef UNICODE
    wcscpy_s(szApplicationPath, argv[1]);
#else
    mbsrtowcs_s(nullptr, szApplicationPath, &argv[1], dwApplicationPathSize - 1, nullptr);
#endif

    // Get Username, Domain, and Password from the environment variables
    wchar_t szUsername[64]{ 0 }, szDomain[64]{ 0 }, szPassword[64]{ 0 };
    GetEnvironmentVariableW(L"Username", szUsername, sizeof(szUsername) / sizeof(szUsername[0]));
    GetEnvironmentVariableW(L"Domain", szDomain, sizeof(szDomain) / sizeof(szDomain[0]));
    GetEnvironmentVariableW(L"Password", szPassword, sizeof(szPassword) / sizeof(szPassword[0]));

    // Run functions
    HANDLE hTableArr[3];
    hTableArr[0] = RunCreateProcess(szApplicationPath);
    hTableArr[1] = RunCreateProcessWithLogon(szApplicationPath, szUsername, szDomain, szPassword);
    hTableArr[2] = RunCreateProcessWithToken(szApplicationPath);

    // Wait for processes to finish
    WaitForSingleObject(hTableArr[0], INFINITE); CloseHandle(hTableArr[0]);
    WaitForSingleObject(hTableArr[1], INFINITE); CloseHandle(hTableArr[1]);
    WaitForSingleObject(hTableArr[2], INFINITE); CloseHandle(hTableArr[2]);

    return 0;
}
