

### Android

#### Sample C app in Android Studio

* https://android.stackexchange.com/questions/69108/how-to-start-root-shell-with-android-studio
* https://amccormack.net/2012-11-03-getting-started-arm-assembly-for-android.html
* https://community.arm.com/
* https://sourceware.org/binutils/docs-2.23/as/index.html
* https://medium.com/@urish/writing-your-first-android-app-in-assembly-30e8e0f8c3fe

cd /Users/<User>/Library/Android/sdk/platform-tools

```
#include <jni.h>
#include <string>

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_myapplication_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello Folks. This is a c code";
    return env->NewStringUTF(hello.c_str());
}

```

#### Sample native app in Android Studio

* https://peterdn.com/post/2019/02/03/hello-world-in-arm-assembly/

Toolchain

```
$ cd /Users/lasalle/Library/Android/sdk/ndk-bundle/toolchains
$ ls
aarch64-linux-android-4.9	llvm				x86-4.9
arm-linux-androideabi-4.9	renderscript			x86_64-4.9

$ cd /Users/lasalle/Library/Android/sdk/ndk-bundle/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64

$ ls 
arm-linux-androideabi	bin			lib			share

$ cd /Users/lasalle/Library/Android/sdk/ndk-bundle/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/arm-linux-androideabi/bin

$ ls -a
.	..	ar	as	hello.S	hello.o	ld	ld.bfd	ld.gold	nm	objcopy	objdump	ranlib	readelf	strip

./as -o hello.o hello.S
./ld -s -o hello hello.o


$ export PATH=$PATH:/Users/lasalle/Library/Android/sdk/platform-tools
$ adb devices
List of devices attached
DEV1	device

$ adb push hello /data/local/tmp/hello
hello: 1 file pushed. 0.0 MB/s (560 bytes in 0.013s)

$ adb shell /data/local/tmp/hello
Hello, ARM!

$ adb shell 'ls -al /data/local/tmp/hello'
-rwxrwxrwx 1 shell shell 560 2019-06-07 04:19 /data/local/tmp/hello

$ adb shell 'ls -al /data/local/tmp'
total 32
drwxrwx--x 2 shell shell 4096 2019-06-07 04:24 .
drwxr-x--x 4 root  root  4096 2017-12-31 18:01 ..
-rw-rw-rw- 1 shell shell   13 2019-06-07 04:05 com.example.myapplication-build-id.txt
-rwxrwxrwx 1 shell shell  560 2019-06-07 04:19 hello


```

hello.S

```
.data

/* Data segment: define our message string and calculate its length. */
msg:
    .ascii      "Hello, ARM!\n"
len = . - msg

.text

/* Our application's entry point. */
.globl _start
_start:
    /* syscall write(int fd, const void *buf, size_t count) */
    mov     %r0, $1     /* fd := STDOUT_FILENO */
    ldr     %r1, =msg   /* buf := msg */
    ldr     %r2, =len   /* count := len */
    mov     %r7, $4     /* write is syscall #4 */
    swi     $0          /* invoke syscall */

    /* syscall exit(int status) */
    mov     %r0, $0     /* status := 0 */
    mov     %r7, $1     /* exit is syscall #1 */
    swi     $0          /* invoke syscall */
```

