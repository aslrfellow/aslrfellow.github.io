; nasm -f macho64 helloworld64-len.asm && ld -macosx_version_min 10.7.0 -lSystem -o helloworld64-len helloworld64-len.o && ./helloworld64-len

global start


section .text

start:

    mov     rbx, msg        ; move the address of our message string into EBX
    mov     rax, rbx        ; move the address in EBX into EAX as well (Both now point to the same segment in memory)

nextchar:
    cmp     byte [rax], 0   ; compare the byte pointed to by EAX at this address against zero (Zero is an end of string delimiter)
    jz      finished        ; jump (if the zero flagged has been set) to the point in the code labeled 'finished'
    inc     rax             ; increment the address in EAX by one byte (if the zero flagged has NOT been set)
    jmp     nextchar        ; jump to the point in the code labeled 'nextchar'


finished:
    sub     rax, rbx        ; subtract the address in EBX from the address in EAX
                            ; remember both registers started pointing to the same address (see line 15)
                            ; but EAX has been incremented one byte for each character in the message string
                            ; when you subtract one memory address from another of the same type
                            ; the result is number of segments between them - in this case the number of bytes

    mov     rax, 0x2000004 ; write
    mov     rdi, 1 ; stdout
    mov     rsi, msg
    mov     rdx, msg.len
    ;mov     rdx, rax
    syscall

    mov     rax, 0x2000001 ; exit
    mov     rdi, 0
    syscall


section .data

msg:    db      "Hello, world!", 10
.len:   equ     $ - msg
