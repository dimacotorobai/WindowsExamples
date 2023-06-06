#include <iostream>
#include <Windows.h>
#include "ntdll.h"

#pragma comment(lib, "ntdll.lib")

int wmain(int argc, wchar_t* argv[]) {
    LPVOID pMemAlloc = nullptr;
    ULONG bufferLength = 0;

    auto status = NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &bufferLength);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        pMemAlloc = (PSYSTEM_PROCESS_INFORMATION)VirtualAlloc(nullptr, bufferLength, MEM_COMMIT, PAGE_READWRITE);
    }

    status = NtQuerySystemInformation(SystemProcessInformation, pMemAlloc, bufferLength, nullptr);
    if (!NT_SUCCESS(status)) {
        wprintf(L"ERROR - Failed to get process list(0x%X)\n", status);
        if(pMemAlloc) VirtualFree(pMemAlloc, 0, MEM_RELEASE);
        return status;
    }

    PSYSTEM_PROCESS_INFORMATION pProcInfo = (PSYSTEM_PROCESS_INFORMATION)pMemAlloc;
    while (true) {
        wprintf(L"%08X %s\n", HandleToULong(pProcInfo->UniqueProcessId), pProcInfo->ImageName.Buffer);
        if (pProcInfo->NextEntryOffset) pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((uintptr_t)pProcInfo + pProcInfo->NextEntryOffset);
        else break;
    }
    
    VirtualFree(pMemAlloc, 0, MEM_RELEASE);
    return status;
}