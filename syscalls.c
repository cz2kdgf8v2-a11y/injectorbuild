#include "syscalls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #define DEBUG

QN3_SYSCALL_LIST Qn3_SyscallList;

static DWORD Qn3_HashName(PCSTR name) {
    DWORD h = QN3_SEED;
    DWORD i = 0;
    while (name[i]) {
        WORD p = *(WORD*)((ULONG_PTR)name + i++);
        h ^= p + QN3_ROR8(h);
    }
    return h;
}

static PVOID Qn3_FindStub(PVOID apiAddr) {
    const DWORD limit = 512;
    PVOID p;

#ifdef _WIN64
    BYTE  sc[] = { 0x0f, 0x05, 0xc3 };
    ULONG dist = 0x12;
#else
    BYTE  sc[] = { 0x0f, 0x34, 0xc3 };
    ULONG dist = 0x0f;
#endif

    p = QN3_RVA2VA(PVOID, apiAddr, dist);
    if (!memcmp(sc, p, sizeof(sc))) return p;

    for (ULONG j = 1; j < limit; ++j) {
        p = QN3_RVA2VA(PVOID, apiAddr, dist + j * 0x20);
        if (!memcmp(sc, p, sizeof(sc))) return p;
        p = QN3_RVA2VA(PVOID, apiAddr, dist - j * 0x20);
        if (!memcmp(sc, p, sizeof(sc))) return p;
    }
    return NULL;
}

BOOL Qn3_BuildSyscallTable(void) {
    if (Qn3_SyscallList.Count) return TRUE;

#ifdef _WIN64
    PQN3_PEB Peb = (PQN3_PEB)__readgsqword(0x60);
#else
    PQN3_PEB Peb = (PQN3_PEB)__readfsdword(0x30);
#endif

    PQN3_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY Exp = NULL;
    PVOID Base = NULL;

    PQN3_LDR_DATA_TABLE_ENTRY e;
    for (e = (PQN3_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1];
         e->DllBase != NULL;
         e = (PQN3_LDR_DATA_TABLE_ENTRY)e->Reserved1[0]) {

        Base = e->DllBase;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)Base;
        PIMAGE_NT_HEADERS nt  = QN3_RVA2VA(PIMAGE_NT_HEADERS, Base, dos->e_lfanew);
        DWORD va = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (va == 0) continue;

        Exp = (PIMAGE_EXPORT_DIRECTORY)QN3_RVA2VA(ULONG_PTR, Base, va);
        PCHAR nm = QN3_RVA2VA(PCHAR, Base, Exp->Name);

        // "ntdll" via OR 0x20202020 (insensible à la casse)
        if ((*(ULONG*)nm | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(nm + 4) | 0x20202020) == 0x6c642e6c) break;
    }
    if (!Exp) return FALSE;

    DWORD nNames = Exp->NumberOfNames;
    PDWORD funcs = QN3_RVA2VA(PDWORD, Base, Exp->AddressOfFunctions);
    PDWORD names = QN3_RVA2VA(PDWORD, Base, Exp->AddressOfNames);
    PWORD  ords  = QN3_RVA2VA(PWORD,  Base, Exp->AddressOfNameOrdinals);

    DWORD i = 0;
    PQN3_SYSCALL_ENTRY E = Qn3_SyscallList.Entries;
    do {
        PCHAR fn = QN3_RVA2VA(PCHAR, Base, names[nNames - 1]);

        // Détection préfixe "Zw" sans constante signature 0x775a
        if (fn[0] == 'Z' && fn[1] == 'w') {
            E[i].Hash           = Qn3_HashName(fn);
            E[i].Address        = funcs[ords[nNames - 1]];
            E[i].SyscallAddress = Qn3_FindStub(QN3_RVA2VA(PVOID, Base, E[i].Address));
            if (++i == QN3_MAX_ENTRIES) break;
        }
    } while (--nNames);

    Qn3_SyscallList.Count = i;

    // Tri par adresse : l'index trié == SSN (heuristique SysWhispers3).
    for (DWORD a = 0; a + 1 < Qn3_SyscallList.Count; ++a) {
        for (DWORD b = 0; b + a + 1 < Qn3_SyscallList.Count; ++b) {
            if (E[b].Address > E[b + 1].Address) {
                QN3_SYSCALL_ENTRY t = E[b];
                E[b]     = E[b + 1];
                E[b + 1] = t;
            }
        }
    }
    return TRUE;
}

EXTERN_C DWORD Qn3_ResolveSyscallId(DWORD Hash) {
    if (!Qn3_BuildSyscallTable()) return (DWORD)-1;
    for (DWORD i = 0; i < Qn3_SyscallList.Count; ++i)
        if (Hash == Qn3_SyscallList.Entries[i].Hash) return i;
    return (DWORD)-1;
}

EXTERN_C PVOID Qn3_ResolveSyscallStub(DWORD Hash) {
    if (!Qn3_BuildSyscallTable()) return NULL;
    for (DWORD i = 0; i < Qn3_SyscallList.Count; ++i)
        if (Hash == Qn3_SyscallList.Entries[i].Hash)
            return Qn3_SyscallList.Entries[i].SyscallAddress;
    return NULL;
}

EXTERN_C PVOID Qn3_PickSyscallStub(DWORD Hash) {
    if (!Qn3_BuildSyscallTable()) return NULL;

    DWORD count = Qn3_SyscallList.Count;
    if (count < 2) return NULL;

    DWORD idx = (DWORD)rand() % count;
    DWORD guard = 0;
    while (Hash == Qn3_SyscallList.Entries[idx].Hash) {
        idx = (DWORD)rand() % count;
        if (++guard > 256) return Qn3_SyscallList.Entries[(idx + 1) % count].SyscallAddress;
    }
    return Qn3_SyscallList.Entries[idx].SyscallAddress;
}
