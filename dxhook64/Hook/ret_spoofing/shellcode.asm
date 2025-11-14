.CODE
_spoofer_ret PROC
    pop r11                 ; 스택에서 원래 리턴 어드레스를 꺼내서 r11에 저장
    add rsp, 8              ; Shadow Space 8바이트 건너뜀
    mov rax, [rsp + 24]     ; 스택에서 shell_param 구조체 포인터를 rax에 로드
        
    mov r10, [rax]          ; shell_param.trampoline 주소를 r10에 로드 (FF 23 명령어 있는 곳)
    mov [rsp], r10          ; 스택의 리턴 어드레스를 trampoline으로 변조 (가짜 리턴 주소 설정)
        
    mov r10, [rax + 8]      ; shell_param.function (실제 호출할 함수 주소)를 r10에 로드
    mov [rax + 8], r11      ; shell_param.function 위치에 진짜 리턴 어드레스(r11) 저장
     
    mov [rax + 16], rbx     ; 현재 rbx 레지스터 값을 shell_param.register_에 백업
    lea rbx, fixup          ; fixup 레이블 주소를 rbx에 로드
    mov [rax], rbx          ; shell_param.trampoline을 fixup 주소로 덮어씀
    mov rbx, rax            ; shell_param 주소를 rbx에 저장 (나중에 복원용)

    jmp r10                 ; 실제 함수로 점프 (call 대신 jmp 사용)

fixup:                      ; 함수 실행 끝나고 여기로 돌아옴
    sub rsp, 16             ; 스택 16바이트 확보
    mov rcx, rbx            ; shell_param 주소를 rcx로 복원
    mov rbx, [rcx + 16]     ; 백업했던 rbx 레지스터 값 복원
    jmp QWORD PTR [rcx + 8] ; 진짜 리턴 어드레스(r11에 저장했던 값)로 점프
_spoofer_ret ENDP
END