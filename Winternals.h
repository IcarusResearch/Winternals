#pragma once

#include <Windows.h>

typedef struct UNICODE_STRING {
    USHORT              Length;
    USHORT              MaximumLength;
    PWSTR               Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT              UniqueProcessId;
    USHORT              CreatorBackTraceIndex;
    UCHAR               ObjectTypeIndex;
    UCHAR               HandleAttributes;
    USHORT              HandleValue;
    PVOID               Object;
    ULONG               GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO, SYS_HTEI, *PSYS_HTEI;

typedef struct SYSTEM_HANDLE_INFORMATION {
    UINT32              NumberOfHandles;
    SYS_HTEI            Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct OBJECT_ATTRIBUTES {
    ULONG               Length;
    HANDLE              RootDirectory;
    PUNICODE_STRING     ObjectName;
    ULONG               Attributes;
    PVOID               SecurityDescriptor;
    PVOID               SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct CLIENT_ID {
    HANDLE              UniqueProcess;
    HANDLE              UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum SYSTEM_INFORMATION_CLASS {
    // ...
    SystemHandleInformation = 0x10
    // ...
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* fnRtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOL CurrentThread, PBOOL Enabled);
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* fnNtDuplicateObject)(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
typedef NTSTATUS(NTAPI* fnNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

#ifndef WINTERNALS_DISABLE_LINKING
#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOL CurrentThread, PBOOL Enabled);
extern "C" NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
extern "C" NTSTATUS NTAPI NtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
extern "C" NTSTATUS NTAPI NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

#endif
