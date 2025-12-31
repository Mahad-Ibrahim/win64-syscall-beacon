.data
	wSysCall DWORD 0

.code

HellsGate proc
	
	mov DWORD PTR [wSysCall], ecx
	ret
HellsGate ENDP

HellDescent proc

	mov r10, rcx
	mov eax, DWORD PTR [wSysCall]

;	mov r11, qword ptr [rsp+40] not currently implementing call stack spoofing but its still undetectable without it
;    jmp r11
    syscall
    ret


HellDescent ENDP

end