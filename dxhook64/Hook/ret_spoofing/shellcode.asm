.CODE
_spoofer_ret PROC
    pop r11                 ; Pop the original return address into r11
    add rsp, 8              ; Skip 8 bytes of Shadow Space
    mov rax, [rsp + 24]     ; Load the pointer to shell_param struct into rax
        
    mov r10, [rax]          ; Load shell_param.trampoline (address containing 'FF 23' - jmp qword ptr [rbx])
    mov [rsp], r10          ; Overwrite the return address on stack with the trampoline (Spoofed Return Address)
        
    mov r10, [rax + 8]      ; Load shell_param.function (the target function to call) into r10
    mov [rax + 8], r11      ; Store the original return address (r11) into shell_param.function for later recovery
     
    mov [rax + 16], rbx     ; Backup the current rbx register value into shell_param.register_
    lea rbx, fixup          ; Load the address of the 'fixup' label into rbx
    mov [rax], rbx          ; Replace shell_param.trampoline with the fixup address
    mov rbx, rax            ; Store the shell_param pointer in rbx for restoration after the call

    jmp r10                 ; Jump to the target function (Tail call to bypass stack trace)

fixup:                      ; Control flows back here after the target function returns
    sub rsp, 16             ; Adjust stack by 16 bytes to align
    mov rcx, rbx            ; Restore shell_param pointer to rcx
    mov rbx, [rcx + 16]     ; Restore the original rbx register value
    jmp QWORD PTR [rcx + 8] ; Jump back to the original return address (recovered from r11)
_spoofer_ret ENDP
END
