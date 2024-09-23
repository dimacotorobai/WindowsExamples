#include <iostream>
#include <string>
#include <unordered_map>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>


std::unordered_map<DWORD, std::wstring> GetProcessList()
{
    std::unordered_map<DWORD, std::wstring> processList;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        std::cerr << "CreateToolhelp32Snapshot failed. GetLastError =" << GetLastError() << std::endl;
        return processList;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32))
    {
        do {
            processList.insert({ pe32.th32ProcessID, pe32.szExeFile });
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return processList;
}

std::wstring GetProcessName(DWORD processId)
{
    auto processList = GetProcessList();
    if (processList.count(processId) == 0)
    {
        return L"";
    }
    return processList.at(processId);
}

std::wstring GetProcessUsername(HANDLE hToken)
{
    // Get the user information  
    DWORD dwLengthNeeded = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLengthNeeded);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "GetTokenInformation (TokenUser) failed. GetLastError = " << GetLastError() << std::endl;
        return L"";
    }

    PTOKEN_USER pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwLengthNeeded);
    if (pTokenUser == NULL) {
        std::cerr << "LocalAlloc failed. GetLastError = " << GetLastError() << std::endl;
        return L"";
    }

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwLengthNeeded, &dwLengthNeeded)) {
        std::cerr << "GetTokenInformation (TokenUser) failed. GetLastError = " << GetLastError() << std::endl;
        LocalFree(pTokenUser);
        return L"";
    }

    // Convert the SID to a user name  
    TCHAR szName[256];
    TCHAR szDomain[256];
    DWORD dwSizeName = sizeof(szName) / sizeof(TCHAR);
    DWORD dwSizeDomain = sizeof(szDomain) / sizeof(TCHAR);
    SID_NAME_USE SidType;

    if (!LookupAccountSid(NULL, pTokenUser->User.Sid, szName, &dwSizeName, szDomain, &dwSizeDomain, &SidType)) {
        std::cerr << "LookupAccountSid failed. GetLastError = " << GetLastError() << std::endl;
        LocalFree(pTokenUser);
        return L"";
    }

    return std::wstring() + szDomain + L"\\" + szName;
}

std::wstring GetProcessElevation(HANDLE hToken)
{
    TOKEN_ELEVATION elevation;
    DWORD dwSize;
    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
    {
        std::cerr << "GetTokenInformation (TokenElevation) failed. GetLastError = " << GetLastError() << std::endl;
        return L"";
    }

    return elevation.TokenIsElevated ? std::wstring(L"Yes") : std::wstring(L"No");
}

std::wstring GetProcessElevationType(HANDLE hToken)
{
    TOKEN_ELEVATION_TYPE elevationType;
    DWORD dwSize;

    if (!GetTokenInformation(hToken, TokenElevationType, &elevationType, sizeof(elevationType), &dwSize))
    {
        std::cerr << "GetTokenInformation (TokenElevationType) failed. GetLastError = " << GetLastError() << std::endl;
        return L"";
    }

    switch (elevationType)
    {
    case TokenElevationTypeDefault:
        return std::wstring(L"Default (Standard User)");

    case TokenElevationTypeFull:
        return std::wstring(L"Full (Elevated)");

    case TokenElevationTypeLimited:
        return std::wstring(L"Limited (Limited User)");

    default:
        return std::wstring(L"Unknown");
    }
}

std::wstring GetProcessIntegrityLevel(HANDLE hToken)
{
    // Get the integrity level  
    DWORD dwLengthNeeded;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "GetTokenInformation (TokenIntegrityLevel) failed. GetLastError = " << GetLastError() << std::endl;
        return L"";
    }

    PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLengthNeeded);
    if (pTIL == NULL) {
        std::cerr << "LocalAlloc failed. GetLastError = " << GetLastError() << std::endl;
        return L"";
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded)) {
        std::cerr << "GetTokenInformation (TokenIntegrityLevel) failed. GetLastError = " << GetLastError() << std::endl;
        LocalFree(pTIL);
        return L"";
    }

    DWORD dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
    switch (dwIntegrityLevel)
    {
    case SECURITY_MANDATORY_UNTRUSTED_RID:
        return std::wstring(L"Untrusted");

    case SECURITY_MANDATORY_LOW_RID:
        return std::wstring(L"Low");

    case SECURITY_MANDATORY_MEDIUM_RID:
        return std::wstring(L"Medium");

    case SECURITY_MANDATORY_MEDIUM_PLUS_RID:
        return std::wstring(L"Medium Plus");

    case SECURITY_MANDATORY_HIGH_RID:
        return std::wstring(L"High");

    case SECURITY_MANDATORY_SYSTEM_RID:
        return std::wstring(L"System");

    case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:
        return std::wstring(L"Protected");

    default:
        return std::wstring(L"Unknown");
    }
}

int GetProcessInformation(DWORD dwProcessId)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
    if (hProcess == NULL) {
        std::cerr << "OpenProcess failed. GetLastError = " << GetLastError() << std::endl;
        return -1;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed. GetLastError = " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return -1;
    }

    std::wcout << L"Name: " << GetProcessName(dwProcessId) << std::endl;
    std::wcout << L"Elevated: " << GetProcessElevation(hToken) << std::endl;
    std::wcout << L"Type: " << GetProcessElevationType(hToken) << std::endl;
    std::wcout << "Integrity: " << GetProcessIntegrityLevel(hToken) << std::endl;

    return 0;
}

int wmain(int argc, const wchar_t* argv[], const wchar_t* envp[])
{
    if (argc != 2)
    {
        std::wcout << L"Usage: WindowsPrivilegeInformer.exe <PID>" << std::endl;
        return -1;
    }

    DWORD dwPID = _wtoi(argv[1]);
    return GetProcessInformation(dwPID);
}
