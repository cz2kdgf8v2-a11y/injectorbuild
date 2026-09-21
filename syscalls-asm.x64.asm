.code

EXTERN Qn3_ResolveSyscallId: PROC
EXTERN Qn3_PickSyscallStub:  PROC

; -------------------------------------------------------------------------
; Stub générique :
;   [rsp+20h] = sauvegarde de l'adresse du stub (au-dessus du shadow space)
;   EAX       = syscall number (retour de Qn3_ResolveSyscallId)
;   r10       = arg1 (rcx restauré)
;   rdx/r8/r9 = args 2/3/4 (restaurés)
; -------------------------------------------------------------------------

Qn3_NtOpenProcess PROC
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 28h
    mov  ecx, 00DBF0A2Ch
    call Qn3_PickSyscallStub
    mov  [rsp+20h], rax
    mov  ecx, 00DBF0A2Ch
    call Qn3_ResolveSyscallId
    mov  r11, [rsp+20h]
    add  rsp, 28h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    mov  r10, rcx
    jmp  r11
Qn3_NtOpenProcess ENDP

Qn3_NtOpenThread PROC
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 28h
    mov  ecx, 01ABD441Fh
    call Qn3_PickSyscallStub
    mov  [rsp+20h], rax
    mov  ecx, 01ABD441Fh
    call Qn3_ResolveSyscallId
    mov  r11, [rsp+20h]
    add  rsp, 28h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    mov  r10, rcx
    jmp  r11
Qn3_NtOpenThread ENDP

Qn3_NtAllocateVirtualMemory PROC
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 28h
    mov  ecx, 00388131Fh
    call Qn3_PickSyscallStub
    mov  [rsp+20h], rax
    mov  ecx, 00388131Fh
    call Qn3_ResolveSyscallId
    mov  r11, [rsp+20h]
    add  rsp, 28h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    mov  r10, rcx
    jmp  r11
Qn3_NtAllocateVirtualMemory ENDP

Qn3_NtWriteVirtualMemory PROC
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 28h
    mov  ecx, 012991C10h
    call Qn3_PickSyscallStub
    mov  [rsp+20h], rax
    mov  ecx, 012991C10h
    call Qn3_ResolveSyscallId
    mov  r11, [rsp+20h]
    add  rsp, 28h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    mov  r10, rcx
    jmp  r11
Qn3_NtWriteVirtualMemory ENDP

Qn3_NtProtectVirtualMemory PROC
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 28h
    mov  ecx, 00E93061Ch
    call Qn3_PickSyscallStub
    mov  [rsp+20h], rax
    mov  ecx, 00E93061Ch
    call Qn3_ResolveSyscallId
    mov  r11, [rsp+20h]
    add  rsp, 28h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    mov  r10, rcx
    jmp  r11
Qn3_NtProtectVirtualMemory ENDP

Qn3_NtSuspendThread PROC
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 28h
    mov  ecx, 0A8836621h
    call Qn3_PickSyscallStub
    mov  [rsp+20h], rax
    mov  ecx, 0A8836621h
    call Qn3_ResolveSyscallId
    mov  r11, [rsp+20h]
    add  rsp, 28h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    mov  r10, rcx
    jmp  r11
Qn3_NtSuspendThread ENDP

Qn3_NtResumeThread PROC
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 28h
    mov  ecx, 0A7009982h
    call Qn3_PickSyscallStub
    mov  [rsp+20h], rax
    mov  ecx, 0A7009982h
    call Qn3_ResolveSyscallId
    mov  r11, [rsp+20h]
    add  rsp, 28h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    mov  r10, rcx
    jmp  r11
Qn3_NtResumeThread ENDP

Qn3_NtGetContextThread PROC
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 28h
    mov  ecx, 02EAE6E6Dh
    call Qn3_PickSyscallStub
    mov  [rsp+20h], rax
    mov  ecx, 02EAE6E6Dh
    call Qn3_ResolveSyscallId
    mov  r11, [rsp+20h]
    add  rsp, 28h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    mov  r10, rcx
    jmp  r11
Qn3_NtGetContextThread ENDP

Qn3_NtSetContextThread PROC
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 28h
    mov  ecx, 0953ECF80h
    call Qn3_PickSyscallStub
    mov  [rsp+20h], rax
    mov  ecx, 0953ECF80h
    call Qn3_ResolveSyscallId
    mov  r11, [rsp+20h]
    add  rsp, 28h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    mov  r10, rcx
    jmp  r11
Qn3_NtSetContextThread ENDP

Qn3_NtClose PROC
    push rcx
    push rdx
    push r8
    push r9
    sub  rsp, 28h
    mov  ecx, 01A942CCFh
    call Qn3_PickSyscallStub
    mov  [rsp+20h], rax
    mov  ecx, 01A942CCFh
    call Qn3_ResolveSyscallId
    mov  r11, [rsp+20h]
    add  rsp, 28h
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    mov  r10, rcx
    jmp  r11
Qn3_NtClose ENDP

end
