#include "syscalls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Décommente pour voir la progression (utile pour trouver où ça crash)
#define QN3_DEBUG

#ifdef QN3_DEBUG
  #define DBGS(...) printf(__VA_ARGS__)
#else
  #define DBGS(...) ((void)0)
#endif

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

// Recherche SAFE : forward uniquement, bornée. Pas d'underflow possible.
static PVOID Qn3_FindStub(PVOID apiAddr) {
    BYTE  sc[3] = { 0x0f, 0x05, 0xc3 };   // syscall; ret
    const ULONG dist = 0x12;
    ULONG_PTR base = (ULONG_PTR)apiAddr;

    // Chemin rapide : pattern à l'offset exact.
    PVOID p = (PVOID)(base + dist);
    if (memcmp(sc, p, 3) == 0) return p;

    // Forward borné : jamais plus de 0x2000 octets après le début de la fonction.
    for (DWORD off = 0x20; off <= 0x2000; off += 0x20) {
        p = (PVOID)(base + off);
        if (memcmp(sc, p, 3) == 0) return p;
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
    DBGS("[Qn3] PEB = %p\n", Peb);

    PQN3_PEB_LDR_DATA Ldr = Peb->Ldr;
    DBGS("[Qn3] Ldr = %p\n", Ldr);

    PIMAGE_EXPORT_DIRECTORY Exp = NULL;
    PVOID Base = NULL;
    PQN3_LDR_DATA_TABLE_ENTRY e;

    for (e = (PQN3_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1];
         e != NULL && e->DllBase != NULL;
         e = (PQN3_LDR_DATA_TABLE_ENTRY)e->Reserved1[0]) {

        Base = e->DllBase;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)Base;
        if (dos->e_magic != 0x5A4D) continue;   // 'MZ' guard

        PIMAGE_NT_HEADERS nt = QN3_RVA2VA(PIMAGE_NT_HEADERS, Base, dos->e_lfanew);
        if (nt->Signature != 0x00004550) continue;  // 'PE\0\0' guard

        DWORD va = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (va == 0) continue;

        Exp = (PIMAGE_EXPORT_DIRECTORY)QN3_RVA2VA(ULONG_PTR, Base, va);
        PCHAR nm = QN3_RVA2VA(PCHAR, Base, Exp->Name);
        DBGS("[Qn3] module: %s @ %p\n", nm, Base);

        if ((*(ULONG*)nm | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(nm + 4) | 0x20202020) == 0x6c642e6c) break;
    }
    if (!Exp) { DBGS("[Qn3] ntdll not found\n"); return FALSE; }

    DWORD nNames = Exp->NumberOfNames;
    DBGS("[Qn3] ntdll exports = %lu\n", nNames);

    PDWORD funcs = QN3_RVA2VA(PDWORD, Base, Exp->AddressOfFunctions);
    PDWORD names = QN3_RVA2VA(PDWORD, Base, Exp->AddressOfNames);
    PWORD  ords  = QN3_RVA2VA(PWORD,  Base, Exp->AddressOfNameOrdinals);

    DWORD i = 0;
    DWORD nullCount = 0;
    PQN3_SYSCALL_ENTRY E = Qn3_SyscallList.Entries;
    do {
        PCHAR fn = QN3_RVA2VA(PCHAR, Base, names[nNames - 1]);

        if (fn[0] == 'Z' && fn[1] == 'w') {
            E[i].Hash    = Qn3_HashName(fn);
            E[i].Address = funcs[ords[nNames - 1]];

            PVOID fnVA = QN3_RVA2VA(PVOID, Base, E[i].Address);
            E[i].SyscallAddress = Qn3_FindStub(fnVA);

            if (E[i].SyscallAddress == NULL) {
                nullCount++;
                DBGS("[Qn3] !! no stub for %s @ %p\n", fn, fnVA);
            }
            if (++i == QN3_MAX_ENTRIES) break;
        }
    } while (--nNames);

    Qn3_SyscallList.Count = i;
    DBGS("[Qn3] collected %lu entries, %lu with NULL stub\n", i, nullCount);

    // Tri par adresse → l'index trié == SSN (heuristique SysWhispers3).
    for (DWORD a = 0; a + 1 < Qn3_SyscallList.Count; ++a) {
        for (DWORD b = 0; b + a + 1 < Qn3_SyscallList.Count; ++b) {
            if (E[b].Address > E[b + 1].Address) {
                QN3_SYSCALL_ENTRY t = E[b];
                E[b] = E[b + 1];
                E[b + 1] = t;
            }
        }
    }
    DBGS("[Qn3] table built OK\n");
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

    // ⚠️  On ne tire QUE parmi les entrées avec un stub valide ET différent du hash.
    //     Évite de retourner NULL → jmp NULL → AV.
    DWORD count = Qn3_SyscallList.Count;
    DWORD tries = 0;
    DWORD idx;

    do {
        idx = (DWORD)rand() % count;
        if (++tries > 512) {
            // Fallback : premier stub non-NULL.
            for (DWORD k = 0; k < count; ++k) {
                if (Qn3_SyscallList.Entries[k].SyscallAddress != NULL)
                    return Qn3_SyscallList.Entries[k].SyscallAddress;
            }
            return NULL;
        }
    } while (Hash == Qn3_SyscallList.Entries[idx].Hash ||
             Qn3_SyscallList.Entries[idx].SyscallAddress == NULL);

    return Qn3_SyscallList.Entries[idx].SyscallAddress;
}
