; nasm -f macho64 helloworld64.asm && ld -macosx_version_min 10.7.0 -lSystem -o helloworld64 helloworld64.o && ./helloworld64

global start


section .text

start:
    mov     rax, 0x2000004 ; write
    mov     rdi, 1 ; stdout
    mov     rsi, msg
    mov     rdx, msg.len
    syscall

section .data

msg:    db      "Hello, world!", 10
.len:   equ     $ - msg
