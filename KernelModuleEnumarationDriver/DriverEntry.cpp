#include <ntddk.h>
#include "structs.h"

#define PRINT(x,...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, x, __VA_ARGS__)

void DriverUnload(PDRIVER_OBJECT pDriverObject) {
    UNREFERENCED_PARAMETER(pDriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
    UNREFERENCED_PARAMETER(pRegistryPath);
    pDriverObject->DriverUnload = DriverUnload;

    ULONG bufferSize = 0;
    RtlQueryModuleInformation(&bufferSize, sizeof(RTL_MODULE_EXTENDED_INFO), nullptr);
    
    if (PVOID buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, 'AMID'))  {
        ULONG bufferSize2 = bufferSize;
        RtlZeroMemory(buffer, bufferSize);
        RtlQueryModuleInformation(&bufferSize, sizeof(RTL_MODULE_EXTENDED_INFO), buffer);
        
        if (bufferSize != bufferSize2) {
            PRINT("Error - Buffer size has changed on second call\n");
            if (buffer) ExFreePool(buffer);
            return STATUS_BUFFER_TOO_SMALL;
        }

        PRTL_MODULE_EXTENDED_INFO pModuleList = (PRTL_MODULE_EXTENDED_INFO)buffer;
        do {
            ANSI_STRING modName;
            RtlInitAnsiString(&modName, (const char*)(pModuleList->FullPathName));
            ULONG modBase1 = ((ULONG64)pModuleList->BasicInfo.ImageBase & 0xFFFFFFFF00000000) >> 32;
            ULONG modBase2 = ((ULONG64)pModuleList->BasicInfo.ImageBase & 0x00000000FFFFFFFF) >> 0;
            PRINT("0x%X%X %hZ\n", modBase1, modBase2, modName);

            if ((ULONG64)pModuleList < (ULONG64)buffer + bufferSize)
                pModuleList = (PRTL_MODULE_EXTENDED_INFO)((ULONG64)pModuleList + sizeof(RTL_MODULE_EXTENDED_INFO));
            else break;
        } while (true);

        ExFreePool(buffer);
    }
    return STATUS_SUCCESS;
}