#pragma once

#include <Windows.h>

#define NT_SUCCESS(Status)              (((NTSTATUS) (Status)) >= 0)

#define STATUS_SUCCESS                  (NTSTATUS) 0x00000000L
#define STATUS_INFO_LENGTH_MISMATCH     (NTSTATUS) 0xC0000004L
#define STATUS_ACCESS_VIOLATION         (NTSTATUS) 0xC0000005L
#define STATUS_INVALID_PARAMETER        (NTSTATUS) 0xC000000DL
#define STATUS_NO_MEMORY                (NTSTATUS) 0xC0000017L
#define STATUS_ILLEGAL_INSTRUCTION      (NTSTATUS) 0xC000001DL
#define STATUS_NONCONTINUABLE_EXCEPTION (NTSTATUS) 0xC0000025L
#define STATUS_INVALID_DISPOSITION      (NTSTATUS) 0xC0000026L
#define STATUS_ARRAY_BOUNDS_EXCEEDED    (NTSTATUS) 0xC000008CL
#define STATUS_FLOAT_DENORMAL_OPERAND   (NTSTATUS) 0xC000008DL
#define STATUS_FLOAT_DIVIDE_BY_ZERO     (NTSTATUS) 0xC000008EL
#define STATUS_FLOAT_INEXACT_RESULT     (NTSTATUS) 0xC000008FL
#define STATUS_FLOAT_INVALID_OPERATION  (NTSTATUS) 0xC0000090L
#define STATUS_FLOAT_OVERFLOW           (NTSTATUS) 0xC0000091L
#define STATUS_FLOAT_STACK_CHECK        (NTSTATUS) 0xC0000092L
#define STATUS_FLOAT_UNDERFLOW          (NTSTATUS) 0xC0000093L
#define STATUS_INTEGER_DIVIDE_BY_ZERO   (NTSTATUS) 0xC0000094L
#define STATUS_INTEGER_OVERFLOW         (NTSTATUS) 0xC0000095L
#define STATUS_PRIVILEGED_INSTRUCTION   (NTSTATUS) 0xC0000096L
#define STATUS_STACK_OVERFLOW           (NTSTATUS) 0xC00000FDL
#define STATUS_DLL_NOT_FOUND            (NTSTATUS) 0xC0000135L
#define STATUS_ORDINAL_NOT_FOUND        (NTSTATUS) 0xC0000138L
#define STATUS_NOT_IMPLEMENTED          (NTSTATUS) 0xC0000002L

#define PROCESS_HANDLE_TYPE             0x07

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

typedef enum SE_PRIVILEGE : ULONG {
    SE_CREATE_TOKEN_PRIVILEGE                         = 2,
    SE_ASSIGNPRIMARYTOKEN_PRIVILEGE                   = 3,
    SE_LOCK_MEMORY_PRIVILEGE                          = 4,
    SE_INCREASE_QUOTA_PRIVILEGE                       = 5,
    SE_MACHINE_ACCOUNT_PRIVILEGE                      = 6,
    SE_TCB_PRIVILEGE                                  = 7,
    SE_SECURITY_PRIVILEGE                             = 8,
    SE_TAKE_OWNERSHIP_PRIVILEGE                       = 9,
    SE_LOAD_DRIVER_PRIVILEGE                          = 10,
    SE_SYSTEM_PROFILE_PRIVILEGE                       = 11,
    SE_SYSTEMTIME_PRIVILEGE                           = 12,
    SE_PROF_SINGLE_PROCESS_PRIVILEGE                  = 13,
    SE_INC_BASE_PRIORITY_PRIVILEGE                    = 14,
    SE_CREATE_PAGEFILE_PRIVILEGE                      = 15,
    SE_CREATE_PERMANENT_PRIVILEGE                     = 16,
    SE_BACKUP_PRIVILEGE                               = 17,
    SE_RESTORE_PRIVILEGE                              = 18,
    SE_SHUTDOWN_PRIVILEGE                             = 19,
    SE_DEBUG_PRIVILEGE                                = 20,
    SE_AUDIT_PRIVILEGE                                = 21,
    SE_SYSTEM_ENVIRONMENT_PRIVILEGE                   = 22,
    SE_CHANGE_NOTIFY_PRIVILEGE                        = 23,
    SE_REMOTE_SHUTDOWN_PRIVILEGE                      = 24,
    SE_UNDOCK_PRIVILEGE                               = 25,
    SE_SYNC_AGENT_PRIVILEGE                           = 26,
    SE_ENABLE_DELEGATION_PRIVILEGE                    = 27,
    SE_MANAGE_VOLUME_PRIVILEGE                        = 28,
    SE_IMPERSONATE_PRIVILEGE                          = 29,
    SE_CREATE_GLOBAL_PRIVILEGE                        = 30,
    SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE               = 31,
    SE_RELABEL_PRIVILEGE                              = 32,
    SE_INC_WORKING_SET_PRIVILEGE                      = 33,
    SE_TIME_ZONE_PRIVILEGE                            = 34,
    SE_CREATE_SYMBOLIC_LINK_PRIVILEGE                 = 35,
    SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE    = 36
} SE_PRIVILEGE;

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
