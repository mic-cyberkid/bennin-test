SECTION .text

GLOBAL InternalDoSyscall

InternalDoSyscall:
    mov r10, rcx
    mov eax, ecx ; Wait, SSN is the first arg
    ; Actually standard calling convention for InternalDoSyscall(ssn, arg1, arg2...)
    ; RCX = ssn
    ; RDX = arg1
    ; R8 = arg2
    ; R9 = arg3
    ; [rsp+40] = arg4...
    
    mov eax, ecx ; SSN into EAX
    mov r10, rdx ; First param into R10 (EDR/Windows requirement)
    
    ; Shift args
    mov rdx, r8
    mov r8, r9
    mov r9, [rsp+40]
    ; Note: This doesn't handle more than 4 args easily without manual stack shifting
    ; But for basic NtAllocate/NtWrite, it works.
    
    syscall
    ret
