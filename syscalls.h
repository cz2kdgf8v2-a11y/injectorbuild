#pragma once

#ifndef QN3_HEADER_H_
#define QN3_HEADER_H_

#include <windows.h>

#ifndef _NTDEF_
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS* PNTSTATUS;
#endif

#define QN3_SEED        0x757469BF
#define QN3_ROL8(v)     (v << 8 | v >> 24)
#define QN3_ROR8(v)     (v >> 8 | v << 24)
#define QN3_MAX_ENTRIES 600
#define QN3_RVA2VA(T, B, R) (T)((ULONG_PTR)(B) + (R))

typedef struct _QN3_SYSCALL_ENTRY {
    DWORD Hash;
    DWORD Address;
    PVOID SyscallAddress;
} QN3_SYSCALL_ENTRY, *PQN3_SYSCALL_ENTRY;

typedef struct _QN3_SYSCALL_LIST {
    DWORD Count;
    QN3_SYSCALL_ENTRY Entries[QN3_MAX_ENTRIES];
} QN3_SYSCALL_LIST, *PQN3_SYSCALL_LIST;

typedef struct _QN3_PEB_LDR_DATA {
    BYTE  Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} QN3_PEB_LDR_DATA, *PQN3_PEB_LDR_DATA;

typedef struct _QN3_LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
} QN3_LDR_DATA_TABLE_ENTRY, *PQN3_LDR_DATA_TABLE_ENTRY;

typedef struct _QN3_PEB {
    BYTE  Reserved1[2];
    BYTE  BeingDebugged;
    BYTE  Reserved2[1];
    PVOID Reserved3[2];
    PQN3_PEB_LDR_DATA Ldr;
} QN3_PEB, *PQN3_PEB;

// Exposé publiquement (utilisé par les stubs ASM).
EXTERN_C DWORD Qn3_ResolveSyscallId(DWORD Hash);
EXTERN_C PVOID Qn3_ResolveSyscallStub(DWORD Hash);
EXTERN_C PVOID Qn3_PickSyscallStub(DWORD Hash);

// API interne (utilisée uniquement par syscalls.c).
BOOL Qn3_BuildSyscallTable(void);

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

EXTERN_C NTSTATUS Qn3_NtOpenProcess(
    OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN PCLIENT_ID);

EXTERN_C NTSTATUS Qn3_NtOpenThread(
    OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN PCLIENT_ID);

EXTERN_C NTSTATUS Qn3_NtAllocateVirtualMemory(
    IN HANDLE, IN OUT PVOID*, IN ULONG, IN OUT PSIZE_T, IN ULONG, IN ULONG);

EXTERN_C NTSTATUS Qn3_NtWriteVirtualMemory(
    IN HANDLE, IN PVOID, IN PVOID, IN SIZE_T, OUT PSIZE_T);

EXTERN_C NTSTATUS Qn3_NtProtectVirtualMemory(
    IN HANDLE, IN OUT PVOID*, IN OUT PSIZE_T, IN ULONG, OUT PULONG);

EXTERN_C NTSTATUS Qn3_NtSuspendThread(IN HANDLE, OUT PULONG);

EXTERN_C NTSTATUS Qn3_NtResumeThread(IN HANDLE, IN OUT PULONG);

EXTERN_C NTSTATUS Qn3_NtGetContextThread(IN HANDLE, IN OUT PCONTEXT);

EXTERN_C NTSTATUS Qn3_NtSetContextThread(IN HANDLE, IN PCONTEXT);

EXTERN_C NTSTATUS Qn3_NtClose(IN HANDLE);

#endif
