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

end	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtOpenThread ENDP

Sw3NtAllocateVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 00388131Fh        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 00388131Fh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtAllocateVirtualMemory ENDP

Sw3NtWriteVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 012991C10h        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 012991C10h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtWriteVirtualMemory ENDP

Sw3NtProtectVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 00E93061Ch        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 00E93061Ch        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtProtectVirtualMemory ENDP

Sw3NtSuspendThread PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0A8836621h        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 0A8836621h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtSuspendThread ENDP

Sw3NtResumeThread PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0A7009982h        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 0A7009982h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtResumeThread ENDP

Sw3NtGetContextThread PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 02EAE6E6Dh        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 02EAE6E6Dh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtGetContextThread ENDP

Sw3NtSetContextThread PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0953ECF80h        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 0953ECF80h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtSetContextThread ENDP

Sw3NtClose PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 01A942CCFh        ; Load function hash into ECX.
	call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 01A942CCFh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
Sw3NtClose ENDP

end
