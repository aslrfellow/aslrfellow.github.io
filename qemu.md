
## Ubuntu qemu raspberry pie - not working - keeping for reference

* https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/
* https://azeria-labs.com/writing-arm-assembly-part-1/
* https://github.com/hugsy/gef
* https://github.com/pwndbg/pwndbg
* https://azeria-labs.com/emulate-raspberry-pi-with-qemu/
* https://twitter.com/azeria_labs

```
E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it
https://itsfoss.com/could-not-get-lock-error/
ps aux | grep -i apt
sudo kill -9 <process id>
sudo rm /var/lib/dpkg/lock-frontend

https://azeria-labs.com/emulate-raspberry-pi-with-qemu/

$ fdisk -l 2017-04-10-raspbian-jessie.img 
Disk 2017-04-10-raspbian-jessie.img: 4 GiB, 4285005824 bytes, 8369152 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x402e4a57

Device                          Boot Start     End Sectors Size Id Type
2017-04-10-raspbian-jessie.img1       8192   92159   83968  41M  c W95 FAT32 (LBA)
2017-04-10-raspbian-jessie.img2      92160 8369151 8276992   4G 83 Linux


92160 x 512 = 47185920

sudo mkdir /mnt/raspbian
sudo mount -v -o offset=47185920 -t ext4 ~/qemu_vms/2017-04-10-raspbian-jessie.img /mnt/raspbian
sudo nano /mnt/raspbian/etc/ld.so.preload

wget https://github.com/dhruvvyas90/qemu-rpi-kernel/raw/master/kernel-qemu-4.4.34-jessie


$ sudo umount /mnt/raspbian

$ qemu-system-arm -kernel ~/qemu_vms/kernel-qemu-4.4.34-jessie -cpu arm1176 -m 256 -M versatilepb -serial stdio -append "root=/dev/sda2 rootfstype=ext4 rw" -hda ~/qemu_vms/2017-04-10-raspbian-jessie.img -redir tcp:5022::22 -no-reboot


$  qemu-system-arm -kernel ~/qemu_vms/kernel-qemu-4.4.34-jessie -cpu arm1176 -m 1G -M versatilepb -serial stdio -append "root=/dev/sda2 rootfstype=ext4 rw" -hda ~/qemu_vms/2017-04-10-raspbian-jessie.img -redir tcp:5022::22 -no-reboot

https://hardwaresecurity.training/trainers/azeria/

https://github.com/hugsy/gef

wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh

https://github.com/hugsy/gef/blob/dev/docs/screenshots.md

```

## MacOS qemu arm - not working. keeping for reference

* https://gist.github.com/humbertodias/6237f80df9a4bccf98be298057a82cf2

```
# QEmu
brew install qemu

# Home for out tests
mkdir ~/arm-emu
cd ~/arm-emu

# Download initrd and kernel

wget http://ftp.de.debian.org/debian/dists/jessie/main/installer-armel/20150422+deb8u5/images/versatile/netboot/initrd.gz

wget http://ftp.de.debian.org/debian/dists/jessie/main/installer-armel/20150422+deb8u5/images/versatile/netboot/vmlinuz-3.16.0-6-versatile

# Creating disk
qemu-img create -f qcow2 armdisk.img 1G

# List items
ls 
armdisk.img			initrd.gz			vmlinuz-3.16.0-6-versatile

# Running 
qemu-system-arm -M versatilepb -kernel \
vmlinuz-3.16.0-6-versatile \
-initrd initrd.gz \
-hda armdisk.img \
-append "root=/dev/ram" \
-m 256 

Use mirrors.kernel.org - the first one is not working

## How to emulate a Raspberry Pi (Raspbian Jessie) on Mac OSX (El Capitan)

https://gist.github.com/hfreire/5846b7aa4ac9209699ba

use brew install qemu instead of port install

$QEMU -kernel $RPI_KERNEL \
-cpu arm1176 -m 256 \
-M versatilepb -no-reboot -serial stdio \
-append "root=/dev/sda2 panic=1 rootfstype=ext4 rw init=/bin/bash" \
-hda $RPI_FS

WARNING: Image format was not specified for './2015-11-21-raspbian-jessie.img' and probing guessed raw.
         Automatically detecting the format is dangerous for raw images, write operations on block 0 will be restricted.
         Specify the 'raw' format explicitly to remove the restrictions.

https://unix.stackexchange.com/questions/276480/booting-a-raw-disk-image-in-qemu

$QEMU -kernel $RPI_KERNEL \
-drive format=raw,file=$RPI_FS  \
-cpu arm1176 -m 256 \
-M versatilepb -no-reboot -serial stdio \
-append "root=/dev/sda2 panic=1 rootfstype=ext4 rw init=/bin/bash" 


qemu-system-x86_64 -drive format=raw,file=boot.bin

```
## MacOS

```
https://gist.github.com/JasonGhent/e7deab904b30cbc08a7d

use strech - https://github.com/dhruvvyas90/qemu-rpi-kernel/raw/master/kernel-qemu-4.14.79-stretch

cp kernel-qemu-4.14.79-stretch kernel-qemu

Error: unrecognized/unsupported machine ID (r1 = 0x00000183).

Available machine support:

ID (hex)	NAME
ffffffff	Generic DT based system
ffffffff	ARM-Versatile (Device Tree Support)

qemu-system-arm -kernel kernel-qemu -cpu arm1176 -m 1G -M versatilepb -serial stdio -append "root=/dev/sda2 rootfstype=ext4 rw" -hda raspbian_latest.img-redir tcp:5022::22 -no-reboot

qemu-system-arm -kernel kernel-qemu -cpu arm1176 -m 256 -M versatilepb -no-reboot -serial stdio -append "root=/dev/sda2 panic=1 rootfstype=ext4 rw" -hda raspbian_latest.img -redir tcp:5022::22
```

