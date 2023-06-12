#pragma once
typedef struct _RTL_MODULE_BASIC_INFO {
    PVOID ImageBase;
} RTL_MODULE_BASIC_INFO, * PRTL_MODULE_BASIC_INFO;

typedef struct _RTL_MODULE_EXTENDED_INFO {
    RTL_MODULE_BASIC_INFO BasicInfo;
    ULONG ImageSize;
    USHORT FileNameOffset;
    UCHAR FullPathName[256];
} RTL_MODULE_EXTENDED_INFO, * PRTL_MODULE_EXTENDED_INFO;

extern "C" {
    NTSTATUS NTAPI RtlQueryModuleInformation(PULONG InformationLength, ULONG SizePerModule, PVOID InformationBuffer);
}
