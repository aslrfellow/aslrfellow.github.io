## Welcome to ASLR Fellow

This page will target to provide sample POC to bypass ASLR and DEP using dangling pointer or memmory leak.

### Links 6/16/19

* [using-shellcode]({{ site.url }}/using-shellcode)
* [qemu]({{ site.url }}/qemu)
* [metasploit-manual-install]({{ site.url }}/metasploit-manual-install)
* [ret2libc-dep-nx-bypass]({{ site.url }}/ret2libc-dep-nx-bypass)
* [android]({{ site.url }}/android)


### Shell in assembly and using 'extern C' 6/8/19

* https://www.tutorialspoint.com/assembly_programming/assembly_system_calls.htm
* http://shell-storm.org/shellcode/files/syscalls.html
* https://www.conradk.com/codebase/2017/06/06/x86-64-assembly-from-scratch/
* https://www.csee.umbc.edu/portal/help/nasm/sample.shtml
* https://stackoverflow.com/questions/31369916/unable-to-compile-assembly-usr-bin-ld-i386-architecture-of-input-file-array1
* 

```
System call number
11. sys_execve
Syntax: int sys_execve(struct pt_regs regs)
Source: arch/i386/kernel/process.c
Action: execute program

; Hello World Program - asmtutor.com
; Compile with: nasm -f elf helloworld.asm
; Link with (64 bit systems require elf_i386 option): ld -m elf_i386 helloworld.o -o helloworld
; Run with: ./helloworld
 
SECTION .data
msg2    db      '/bin/sh'
SECTION .text
global  _start
 
_start:
 
    mov     ebx, msg2
    mov     eax, 11
    int     80h

$ gcc -o hello  hello.o
/usr/bin/ld: i386 architecture of input file `hello.o' is incompatible with i386:x86-64 output
collect2: error: ld returned 1 exit status

sudo apt-get install gcc-multilib g++-multilib

gcc -m32 -o hello  hello.o

calling printf

-----
printf1.asm

; printf1.asm   print an integer from storage and from a register
; Assemble:	nasm -f elf -l printf.lst  printf1.asm
; Link:		gcc -o printf1  printf1.o
; Run:		printf1
; Output:	a=5, eax=7

; Equivalent C code
; /* printf1.c  print an int and an expression */
; #include 
; int main()
; {
;   int a=5;
;   printf("a=%d, eax=%d\n", a, a+2);
;   return 0;
; }

; Declare some external functions
;
        extern	printf		; the C function, to be called

        SECTION .data		; Data section, initialized variables

	a:	dd	5		; int a=5;
fmt:    db "a=%d, eax=%d", 10, 0 ; The printf format, "\n",'0'


        SECTION .text                   ; Code section.

        global main		; the standard gcc entry point
main:				; the program label for the entry point
        push    ebp		; set up stack frame
        mov     ebp,esp

	mov	eax, [a]	; put a from store into register
	add	eax, 2		; a+2
	push	eax		; value of a+2
        push    dword [a]	; value of variable a
        push    dword fmt	; address of ctrl string
        call    printf		; Call C function
        add     esp, 12		; pop stack 3 push times 4 bytes

        mov     esp, ebp	; takedown stack frame
        pop     ebp		; same as "leave" op

	mov	eax,0		;  normal, no error, return value
	ret			; return
	
$ nasm -f elf -l printf.lst  printf1.asm
$ gcc -m32 -o printf1  printf1.o
$ ./printf1 
a=5, eax=7

section .rodata
    format: db 'Hello %s', 10, 0
    name:   db 'Conrad', 0

section .text
        global main
        extern printf
    main:
        ; printf(format, name)
        mov rdi, format
        mov rsi, name
        ; no XMM registers
        mov rax, 0
        call printf
        ; return 0
        mov rax, 0
        ret

sudo apt-get install gcc-multilib g++-multilib
nasm hello.s -f elf64 -o hello.o && gcc -m32 -Wall -Wextra -Werror -o hello hello.o

; printf2.asm  use "C" printf on char, string, int, double
; 
; Assemble:	nasm -f elf -l printf2.lst  printf2.asm
; Link:		gcc -o printf2  printf2.o
; Run:		printf2
; Output:	
;Hello world: a string of length 7 1234567 6789ABCD 5.327000e-30 -1.234568E+302
; 
; A similar "C" program
; #include 
; int main()
; {
;   char   char1='a';         /* sample character */
;   char   str1[]="string";   /* sample string */
;   int    int1=1234567;      /* sample integer */
;   int    hex1=0x6789ABCD;   /* sample hexadecimal */
;   float  flt1=5.327e-30;    /* sample float */
;   double flt2=-123.4e300;   /* sample double */
; 
;   printf("Hello world: %c %s %d %X %e %E \n", /* format string for printf */
;          char1, str1, int1, hex1, flt1, flt2);
;   return 0;
; }


        extern printf                   ; the C function to be called

        SECTION .data                   ; Data section

msg:    db "Hello world: %c %s of length %d %d %X %e %E",10,0
					; format string for printf
char1:	db	'a'			; a character 
str1:	db	"string",0	        ; a C string, "string" needs 0
len:	equ	$-str1			; len has value, not an address
inta1:	dd	1234567		        ; integer 1234567
hex1:	dd	0x6789ABCD	        ; hex constant 
flt1:	dd	5.327e-30		; 32-bit floating point
flt2:	dq	-123.456789e300	        ; 64-bit floating point

	SECTION .bss
		
flttmp:	resq 1			        ; 64-bit temporary for printing flt1
	
        SECTION .text                   ; Code section.

        global	main		        ; "C" main program 
main:				        ; label, start of main program
	 
	fld	dword [flt1]	        ; need to convert 32-bit to 64-bit
	fstp	qword [flttmp]          ; floating load makes 80-bit,
	                                ; store as 64-bit
	                                ; push last argument first
	push	dword [flt2+4]	        ; 64 bit floating point (bottom)
	push	dword [flt2]	        ; 64 bit floating point (top)
	push	dword [flttmp+4]        ; 64 bit floating point (bottom)
	push	dword [flttmp]	        ; 64 bit floating point (top)
	push	dword [hex1]	        ; hex constant
	push	dword [inta1]	        ; integer data pass by value
	push	dword len	        ; constant pass by value
	push	dword str1		; "string" pass by reference 
        push    dword [char1]		; 'a'
        push    dword msg		; address of format string
        call    printf			; Call C function
        add     esp, 40			; pop stack 10*4 bytes

        mov     eax, 0			; exit code, 0=normal
        ret				; main returns to operating system
 
```

### Stack values 6/3/2019

```
(gdb) bt
#0  0x080480aa in strlen ()
(gdb) select-frame 0
(gdb) info frame
Stack level 0, frame at 0x0:
 eip = 0x80480aa in strlen; saved eip = <not saved>
 Outermost frame: outermost
 Arglist at unknown address.
 Locals at unknown address, Previous frame's sp in esp
(gdb) info locals
No symbol table info available.


(gdb) x/32x $sp
0xffffd1c8:	0x00	0x00	0x00	0x00	0x8a	0x80	0x04	0x08
0xffffd1d0:	0x01	0x00	0x00	0x00	0x85	0xd3	0xff	0xff
0xffffd1d8:	0x00	0x00	0x00	0x00	0xc1	0xd3	0xff	0xff
0xffffd1e0:	0xd7	0xd3	0xff	0xff	0xc3	0xd9	0xff	0xff
(gdb) disas
Dump of assembler code for function strlen:
   0x080480a9 <+0>:	push   %ebx
=> 0x080480aa <+1>:	mov    %eax,%ebx
End of assembler dump.
(gdb) i r
eax            0x80490b8	134516920
ecx            0x0	0
edx            0x0	0
ebx            0x0	0
esp            0xffffd1c8	0xffffd1c8
ebp            0x0	0x0
esi            0x0	0
edi            0x0	0
eip            0x80480aa	0x80480aa <strlen+1>
eflags         0x202	[ IF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x0	0
(gdb) 


(gdb) x/20xw $esp
0xffffd1cc:	0x0804808a	0x00000001	0xffffd385	0x00000000
0xffffd1dc:	0xffffd3c1	0xffffd3d7	0xffffd9c3	0xffffd9e5
0xffffd1ec:	0xffffd9fc	0xffffda0b	0xffffda1c	0xffffda27
0xffffd1fc:	0xffffda53	0xffffda73	0xffffda87	0xffffda98
0xffffd20c:	0xffffdaa3	0xffffdacc	0xffffdadd	0xffffdaea

bt

info frame


```

### Debugging 6/2/19

* http://www.unknownroad.com/rtfm/gdbtut/gdbbreak.html#LIST
* http://web.cecs.pdx.edu/~apt/cs491/gdb.pdf
* http://dbp-consulting.com/tutorials/debugging/basicAsmDebuggingGDB.html
* https://cs61.seas.harvard.edu/wiki/Useful_GDB_commands
* https://stackoverflow.com/questions/22801152/understand-cmpb-and-loops-in-assembly-language
* http://www.unknownroad.com/rtfm/gdbtut/gdbstack.html
* ftp://ftp.gnu.org/old-gnu/Manuals/gdb/html_chapter/gdb_7.html


### Sample 05/05/19

* [1-64-asm-hello-world]({{ site.url }}/docs/1-64-asm-hello-world.pdf)
* [2-64-asm-hello-world-triangle-puts-fibo.pdf]({{ site.url }}/docs/2-64-asm-hello-world-triangle-puts-fibo.pdf)

### ASLR Links 05/02/19
- [How to gain root with CVE-2018-4193 in < 10s 16th of February 2019 OffensiveCon 2019 Eloi Benoist-Vanderbeken](https://www.synacktiv.com/ressources/OffensiveCon_2019_macOS_how_to_gain_root_with_CVE-2018-4193_in_10s.pdf)
- [A Methodical Approach to Browser Exploitation The Exploit Development Lifecycle, From A to Z(ero Day)](https://blog.ret2.io/2018/06/05/pwn2own-2018-exploit-development/)
- [Clone this repo to build Frida https://www.frida.re](https://github.com/frida/frida)

### ASLR Links 05/02/19

- [Billy Ellis](https://www.youtube.com/channel/UCk2sx_3FUkKvDGlIhdUQa8A)
- [How to Bypass ASLR using an Information Leak (for Stack Overflow Exploit)](https://www.youtube.com/watch?v=Pht6y4p63SE)
- [Linux Stack Based Buffer Overflow ASLR Bypass](https://www.youtube.com/watch?v=GddYLYlaclY)
- [Memory leakage and bypassing ASLR (Full Exploit)](https://cyrussh.com/?p=239)
- [More Mac OS X and iPhone sandbox escapes and kernel bugs](https://googleprojectzero.blogspot.com/2014/10/more-mac-os-x-and-iphone-sandbox.html)


### Assembly Links 05/01/19

- [SecurityLab.ru](https://www.securitylab.ru)
- [android-ndk/camera/texture-view/src/main/cpp at master · googlesamples/android-ndk](https://github.com/googlesamples/android-ndk/tree/master/camera/texture-view/src/main/cpp)
- [Samples: Overview - Android NDK - Android Developers](https://developer.android.com/ndk/samples)
- [Getting Started ARM Assembly for Android amccormack.net](https://developer.android.com/ndk)
- [Writing 64 bit assembly on Mac OS X - Carpe diem](http://www.idryman.org/blog/2014/12/02/writing-64-bit-assembly-on-mac-os-x/)
- [assembly - nasm - cant link object file with ld on macOS Mojave - Stack Overflow](https://stackoverflow.com/questions/52830484/nasm-cant-link-object-file-with-ld-on-macos-mojave?noredirect=1&lq=1)
- [Ghidra](https://www.nsa.gov/resources/everyone/ghidra)
- [GDB (Step by Step Introduction) - GeeksforGeeks](https://www.geeksforgeeks.org/gdb-step-by-step-introduction/)
- [ICS 46: GDB Installation on Mac OS X](https://www.ics.uci.edu/~pattis/common/handouts/macmingweclipse/allexperimental/mac-gdb-install.html)
- [Welcome to LLDB documentation! — LLDB 8 documentation](https://lldb.llvm.org/)
- [IDA Support: Freeware Version](https://www.hex-rays.com/products/ida/support/download_freeware.shtml)
- [Writing 64 bit assembly on Mac OS X - Carpe diem (Felix blog)](http://www.idryman.org/blog/2014/12/02/writing-64-bit-assembly-on-mac-os-x/)
- [How to write an assembly &#39;hello world on macOS](https://jameshfisher.com/2017/02/20/macos-assembly-hello-world/)
- [Writing your own programming language and compiler with Python](https://blog.usejournal.com/writing-your-own-programming-language-and-compiler-with-python-a468970ae6df)
- [Netwide Assembler - Wikipedia](https://en.wikipedia.org/wiki/Netwide_Assembler)
- [Apple Dev Introduction](https://developer.apple.com/library/archive/documentation/DeveloperTools/Reference/Assembler/000-Introduction/introduction.html#//apple_ref/doc/uid/TP30000851)
- [mpx-linux64-abi.pdf](https://software.intel.com/sites/default/files/article/402129/mpx-linux64-abi.pd)
- [Application Binary Interface (ABI) – Arm Developer](https://developer.arm.com/architectures/system-architectures/software-standards/abi)
- [gabi41.pdf](http://www.sco.com/developers/devspecs/gabi41.pdf)
- [JonathanWakely-What Is An ABI And Why Is It So Complicated.pdf](https://accu.org/content/conf2015/JonathanWakely-What%20Is%20An%20ABI%20And%20Why%20Is%20It%20So%20Complicated.pdf)
- [C++ ABI Summary](https://itanium-cxx-abi.github.io/cxx-abi/)
- [System V ABI - OSDev Wiki](https://wiki.osdev.org/System_V_ABI)
- [MacOS System Call List - https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)
- [NASM Assembly Language Tutorials - asmtutor.com](https://asmtutor.com/#lesson1)
- [Making system calls from Assembly in Mac OS X PyTux](https://filippo.io/making-system-calls-from-assembly-in-mac-os-x/)
- [NASM Assembly Language Tutorials - asmtutor.com](https://asmtutor.com/)
- [DGivney/assemblytutorials: This project was put together to teach myself NASM assembly language on linux.](https://github.com/DGivney/assemblytutorials)

### Maintenance

- [Wiki Pattern](/pattern)

### Custom OS
brew install qemu
qemu-system-x86_64 -drive format=raw,file=boot.bin

* https://github.com/ghaiklor/ghaiklor-os-gcc/blob/master/cpu/idt.c
* https://blog.ghaiklor.com/how-to-implement-your-own-hello-world-boot-loader-c0210ef5e74b



