---
layout: post
title: "Scripting GDB For Fun And Profit -- Or How To Automate The Boring Stuff With GDB"
date: 2023-04-02
categories: c python rev pwn
---

# Introduction
It's been years since I started using GDB and I'm still using it the same way.
A lot of stepping and nexting, a breakpoint there and there, some printing and
hexdumping. So I thought that it's finally time to change it and spend some
time exploring automation in GDB. So that's what I did - I spend a day
researching things around to improve my GDB-fu. Because finding some specific
information included going through github issues, reading stackoverflow
comments and skimming through documentations, I decided to write a blogpost
gathering all the things I've learned and would love to be a little more
accessible. I'm writing from a perspective of reverse engineering and exploit
development where we don't have debugging symbols with the binary but
everything there should be useful for regular debugging too. Everyone in the cybersec
community uses plugins for GDB to make it more usable so if you don't I
recommend using them too. Personally I always used pwndbg and the
blogpost is written with some tips for it but there's also gef and
GDB-dashboard. We'll start with the basics, how to make simple GDB scripts if you
don't know it already, then we'll explore the tight integration of Python with
GDB, and we will wrap it up showing how to better use the Python's exploit
development library `pwntools`'s GDB integration. And if this wasn't obvious
already - I will assume that you have some GDB experience, just none when it
comes to scripting it.

# Basic GDB Scripting
All the testing will be done on this very simple c program:
```c
#include <stdio.h>

int main() {
    getchar();
    int a[32] = {0};
    for (int i = 0; i < 32; i++) {
        a[i] = i * 2;
    }

    for (int i = 0; i < 32; i++) {
        printf("%d\n", a[i]);
    }

    return 0;
}
```
The `getchar` is there so we can easily attach GDB to the process if needed.
The source code is compiled with the command `gcc a.c`. There's the disassembly
of our main function:
```c
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0000555555555159 <+0>: 	push   rbp
   0x000055555555515a <+1>: 	mov    rbp,rsp
   0x000055555555515d <+4>: 	sub    rsp,0xa0
   0x0000555555555164 <+11>:	mov    rax,QWORD PTR fs:0x28
   0x000055555555516d <+20>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000555555555171 <+24>:	xor    eax,eax
   0x0000555555555173 <+26>:	call   0x555555555050 <getchar@plt>
   0x0000555555555178 <+31>:	lea    rdx,[rbp-0x90]
   0x000055555555517f <+38>:	mov    eax,0x0
   0x0000555555555184 <+43>:	mov    ecx,0x10
   0x0000555555555189 <+48>:	mov    rdi,rdx
   0x000055555555518c <+51>:	rep stos QWORD PTR es:[rdi],rax
   0x000055555555518f <+54>:	mov    DWORD PTR [rbp-0x98],0x0
   0x0000555555555199 <+64>:	jmp    0x5555555551ba <main+97>
   0x000055555555519b <+66>:	mov    eax,DWORD PTR [rbp-0x98]
   0x00005555555551a1 <+72>:	lea    edx,[rax+rax*1]
   0x00005555555551a4 <+75>:	mov    eax,DWORD PTR [rbp-0x98]
   0x00005555555551aa <+81>:	cdqe
   0x00005555555551ac <+83>:	mov    DWORD PTR [rbp+rax*4-0x90],edx
   0x00005555555551b3 <+90>:	add    DWORD PTR [rbp-0x98],0x1
   0x00005555555551ba <+97>:	cmp    DWORD PTR [rbp-0x98],0x1f
   0x00005555555551c1 <+104>:	jle    0x55555555519b <main+66>
   0x00005555555551c3 <+106>:	mov    DWORD PTR [rbp-0x94],0x0
   0x00005555555551cd <+116>:	jmp    0x5555555551fb <main+162>
   0x00005555555551cf <+118>:	mov    eax,DWORD PTR [rbp-0x94]
   0x00005555555551d5 <+124>:	cdqe
   0x00005555555551d7 <+126>:	mov    eax,DWORD PTR [rbp+rax*4-0x90]
   0x00005555555551de <+133>:	mov    esi,eax
   0x00005555555551e0 <+135>:	lea    rax,[rip+0xe1d]        # 0x555555556004
   0x00005555555551e7 <+142>:	mov    rdi,rax
   0x00005555555551ea <+145>:	mov    eax,0x0
   0x00005555555551ef <+150>:	call   0x555555555040 <printf@plt>
   0x00005555555551f4 <+155>:	add    DWORD PTR [rbp-0x94],0x1
   0x00005555555551fb <+162>:	cmp    DWORD PTR [rbp-0x94],0x1f
   0x0000555555555202 <+169>:	jle    0x5555555551cf <main+118>
   0x0000555555555204 <+171>:	mov    eax,0x0
   0x0000555555555209 <+176>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x000055555555520d <+180>:	sub    rdx,QWORD PTR fs:0x28
   0x0000555555555216 <+189>:	je     0x55555555521d <main+196>
   0x0000555555555218 <+191>:	call   0x555555555030 <__stack_chk_fail@plt>
   0x000055555555521d <+196>:	leave
   0x000055555555521e <+197>:	ret
End of assembler dump.
pwndbg>
```
One of the simplest and most useful tricks in GDB is to put a breakpoint
somewhere and define some commands that are executed when we hit the breakpoint,
but at the end of the block of commands we put a `continue` so we can observe how a
value changes over time. For example we can see in the `main+83` instruction
our newely calculated value being saved in an array.
```assembly
   0x00005555555551ac <+83>:	mov    DWORD PTR [rbp+rax*4-0x90],edx
```
Let's check every loop iteration what the edx register is equal to in this
point.
```
pwndbg> b *main+83
Breakpoint 2 at 0x5555555551ac

pwndbg> commands 2
Type commands for breakpoint(s) 2, one per line.
End with a line saying just "end".
>print $edx
>continue
>end

pwndbg>
```
Now when we run this program we will see every value being written to our
array. Except when you use pwndbg. Even though I love this plugin, it has for
years already a bug where GDB freezes because of the continue. I believe it's
being worked on but at the point of writing this I have the newest version from
github and it still happens to me, so I will tell you how to fix it in case it
happens to you too. There's one of the issues related to it:
`https://github.com/pwndbg/pwndbg/issues/1653`. The fix is to use `python
gdb.execute('continue')` instead of a `continue`. This fixes the issue for me
but sometimes GDB every roughly tenth~ time doesn't continue and you need to
continue by hand. Now I couldn't replicate it, so I guess they fixed it? It's not a
big issue however if that happens to you try to set memoize to off by using the
`memoize` command once. Turning off memoization makes pwndbg noticably slower
so I recommend to turn it on after that by typing the command a second time.
```
pwndbg> b *main+83
Breakpoint 1 at 0x11ac
pwndbg> commands 1
Type commands for breakpoint(s) 1, one per line.
End with a line saying just "end".
>print $edx
>python gdb.execute('continue')
>end
pwndbg> r
Starting program: /home/tabun-dareka/scriptgdb/test/a.out
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".


Breakpoint 1, 0x00005555555551ac in main ()
$1 = 0

Breakpoint 1, 0x00005555555551ac in main ()
$2 = 2

Breakpoint 1, 0x00005555555551ac in main ()
$3 = 4

Breakpoint 1, 0x00005555555551ac in main ()
$4 = 6

...
```

Now let's talk about scripting the control flow in pure GDB. There are `if`
statements, `else` statements (but no else ifs, if you want an `else if` you
need to nest two statements) and `while` statements. There are keywords for
breaks and continues: `loop_break`, `loop_continue`. You can define a function
with a `define` (well... in the documentation they are refered to
as commands not functions). Inside of GDB's "functions" we can run any command
that we can run normally in the repl.


A syntastic sugar for something like:
```
break *main+83
commands
    if $edx <= 30
        continue
    end
end
```
would be:
```
break *main+83 if $edx > 30
```


Let's make a fibonacci function inside of GDB just for the sake of it:
```
define fib
    set $tmp = 0
    set $a = 1 
    set $b = 1 
    set $i = 1
    while $i++ < $arg0
        set $tmp = $b
        set $b = $a
        set $a = $tmp + $b
    end
    print $a
end
```
We can run our defined function by typing `fib 123`. To be honest I haven't
explored much of the GDB scripting language and I don't know where its
limitations are, but I still wouldn't recommend using it cuz doing even simple
things can feel quite cumbersome. Even while writing this example I couldn't find a
way to do this recursively because there was no way of returning the value. For
any complicated logic I would default to the embedded Python, about which we
will talk in the next section of the blogpost.

Another useful trick is to log the GDB output to a file so we can later look
at it or even parse the output somehow. It's especially useful since there's
no redirect the output to a file option. We can log the output by typing:
```
set logging file gdb.output
set logging enable on

*some other commands there*

set logging enable off
```

Also one thing that is not scripting related but that I found while doing
research for this post... turns out you can import structs from other programs
compiled with debugging symbols. This is especially useful while doing dynamic
reverse engineering and there's a struct that you want to print and interact
with in an easier way.
```
➜  structs cat original.c
#include <stdio.h>

typedef struct original_struct {
    int a;
    int b;
    int c;
} OriginalStruct;

OriginalStruct s = {123, 321, 0};

int main() {
    printf("%d", s.b);
    return 0;
}


➜  structs cat recreation.c
typedef struct recreated_struct {
    int x;
    int y;
    int z;
} RecreatedStruct;

// we need to use the struct in the recreated file in some way
// cause otherwise the symbol won't be generated
RecreatedStruct s;


➜  structs gcc original.c
➜  structs gcc -g -c recreation.c
➜  structs ls
a.out  original.c  recreation.c  recreation.o
➜  structs
```
Now when we use GDB on `./a.out`:
```
pwndbg> p s
's' has unknown type; cast it to its declared type

pwndbg> p (struct recreated_struct)s
No struct type named recreated_struct.

pwndbg> add-symbol-file recreation.o
add symbol table from file "recreation.o"
Reading symbols from recreation.o...

pwndbg> p (struct recreated_struct)s
$1 = {
  x = 123,
  y = 321,
  z = 0
}

pwndbg> p (RecreatedStruct)s
$2 = {
  x = 123,
  y = 321,
  z = 0
}

pwndbg>
```

# Python In GDB
Okay, let's now move on to the main dish. We can launch Python inside of GDB in
the following ways:
- With the `python` command, we can use Python in something like a batch mode. We
  type a bunch of lines, we type `end` and all the lines get executed
- With the `pi` or `python-interactive` command we launch Python in a
  REPL. In my opinion this is the best way to interact with Python.
- With the `source script_name.py` command. We execute a given Python script.

By giving either `python` or `pi` a line of code as an argument, then
the line will be executed instead. If you use pwndbg you can also you
the `ipi` command which launches Python in the superior iPython
REPL. Now what can we do with Python inside of GDB? Everything! One
thing that is cool about the Python interpreter there is that it lives
inside of GDB, so it remembers everything we do between the
invocations.

```python
pwndbg> ipi

In [1]: a = 123

In [2]: quit

pwndbg> ipi

In [1]: print(a)
123

In [2]: quit

pwndbg>
```
GDB exposes to us a god object called `gdb` that we can use for everything.
```python
In [1]: gdb
Out[1]: <module 'gdb' from '/usr/share/gdb/python/gdb/__init__.py'>

In [2]: help(gdb)
```
If we want to check everything that is possible with it we can either [read the
docs](https://sourceware.org/gdb/onlinedocs/gdb/Python.html) or use the
Python's built-in help function. So how can we use this object? The most
important method that you will be using all the time is `gdb.execute (command
[, from_tty [, to_string]])`. It takes as an argument a command to execute and
an optional keyword argument `to_string`. If it's set to `True` then the
command instead of returning the output to the screen, we get the output as a
string, so later we can parse it. In theory this method is more than enough but
parsing all the output would be a nightmare so GDB exposes a method for a lot
of things for us. For example we can read an expression's result or register
value in the following ways:
```python
In [1]: gdb.parse_and_eval('$rip')
Out[1]: <gdb.Value at 0x7fb087f99430>

In [2]: gdb.selected_frame().read_register('rip')
Out[2]: <gdb.Value at 0x7fb0873e8cf0>

In [3]: gdb.execute('print $rip', to_string=True)
Out[3]: '$1 = (void (*)()) 0x55555555515d <main+4>\n'
```
But there's no other way to change a register value than using
`gdb.execute('set $rax = 0x10')`. The most important object that we will want to
create is the `Breakpoint` object. Even though it's called a breakpoint, it can
be also used to create watchpoints. The first constructor argument is a string
that holds an expression for the `break` or `watch`. The second argument is
what we want to create. Check [the
docs](https://sourceware.org/gdb/onlinedocs/gdb/Breakpoints-In-Python.html#Breakpoints-In-Python)
for a full description of the available types but you can guess what they do
    just by their names: `gdb.BP_BREAKPOINT`, `gdb.BP_HARDWARE_BREAKPOINT`,
    `gdb.BP_WATCHPOINT`, `gdb.BP_HARDWARE_WATCHPOINT`, `gdb.BP_READ_WATCHPOINT`
    or `gdb.BP_ACCESS_WATCHPOINT`. If you don't specify any, the default is
    your typical breakpoint. If the type is set to a watchpoint breakpoint
    (gdb.BP_WATCHPOINT) then we have to specify a third argument for the
    watchpoint type: `gdb.WP_READ`, `gdb.WP_WRITE` or `gdb.WP_ACCESS`. Now
    after we created our breakpoint it has quite a number of useful methods and
    attributes. For example:
- `Breakpoint.delete()` deletes the breakpoint.
- You can change the `Breakpoint.enabled` attribute to `False` to turn the
  breakpoint off or to `True` to turn it on
- The `Breakpoint.condition` attribute contains a string of the conditional
  expression of the breakpoint. If it evaluates to true then we stop.
- The `Breakpoint.commands` attribute contains the commands executed when
  hitting the breakpoint.

```python
In [1]: bp1 = gdb.Breakpoint("*main")
Breakpoint 3 at 0x555555555159

In [2]: # a random condition

In [3]: bp1.condition = "$rip > 10"

In [4]: bp1.commands = "print $rip\ncontinue"

In [5]: bp = gdb.Breakpoint("*0x7fffffffdb4c", gdb.BP_WATCHPOINT, gdb.WP_WRITE)
Hardware watchpoint 4: *0x7fffffffdb4c

In [6]: bp1 = gdb.Breakpoint("*main+1", gdb.BP_HARDWARE_BREAKPOINT)
Hardware assisted breakpoint 5 at 0x55555555515a
```
But for some reasons the types `gdb.BP_HARDWARE_WATCHPOINT`,
`gdb.BP_READ_WATCHPOINT` and `gdb.BP_ACCESS_WATCHPOINT` that are mentioned in
the documentation don't work for me. Instead, like we can see in the snippet
above, normal watchpoints already use hardware watchpoints so I guess those
types are not needed anyway.
```python
In [7]: bp = gdb.Breakpoint("*0x7fffffffdb4c", gdb.BP_HARDWARE_WATCHPOINT)
---------------------------------------------------------------------------
error                                     Traceback (most recent call last)
Cell In[7], line 1
----> 1 bp = gdb.Breakpoint("*0x7fffffffdb4c", gdb.BP_HARDWARE_WATCHPOINT)

error: Do not understand breakpoint type to set.
```

You can also subclass the gdb.Breakpoint class to create a breakpoint with a
custom `.stop(self)` method. The `stop` method is called every time the breakpoint is
hit and if it returns `True` then it stops and when it returns `False` then it 
continues.
```python
In [12]: import random

In [13]: class EvilBreakpoint(gdb.Breakpoint):
    ...:     def stop(self):
    ...:         return random.choice([False, True])
    ...:

In [14]: bp = EvilBreakpoint("*main+22")
Breakpoint 7 at 0x55555555516f
```

Another thing that I think might is useful is the option to create new
commands. I will not dive deeper into it than a "hello world" example but
if you ever find yourself in a need to create a command to make things easier
or faster for you, [the options is there](
https://sourceware.org/gdb/onlinedocs/gdb/CLI-Commands-In-Python.html#CLI-Commands-In-Python).
```python
In [1]: class MyCommand(gdb.Command):
   ...:     def __init__(self):
   ...:         super(MyCommand, self).__init__("my_command_name", gdb.COMMAND_USER)
   ...:
   ...:     def invoke(self, args, from_tty):
   ...:         print("hewwo!")
   ...:

In [2]: MyCommand()
Out[2]: <__main__.MyCommand at 0x7ff3df20c600>
```
After we define our class we need to instantiate it for GDB to register it.
Now we can call your command by the name we typed.
```
pwndbg> my_command_name
hewwo!
pwndbg>
```

# Abusing GDB In pwntools
If you've ever used pwntools for exploit development then I'm sure you've
already seen that you can pass GDB commands to the `gdb.attach` or 
`gdb.debug` functions through the `gdbscript` argument.
```python
from pwn import *

exe = ELF("./a.out")
context.binary = exe

io = process([exe.path])
gdb.attach(io, gdbscript='''
    break *main
    continue
''')
```
But this is very limiting. We can't access GDB before making a decision what we
want to execute and we can't execute anything after. To the rescue comes
pwntools' integration with GDB that allows us to access the GDB's `gdb` god
object through our script. It's possible thanks to the [RPyC library](
https://rpyc.readthedocs.io/en/latest/) which is super interesting. The only
thing we need to do for it to work is to pass `api=True` as an argument.
```python
from pwn import *

exe = ELF("./a.out")
context.binary = exe

io = gdb.debug([exe.path], aslr=False, api=True)
```
Now we can do anything we've learned in the second blogpost's section about
Python. Neat! For example this is how we define a breakpoint:
```python
bp = io.gdb.Breakpoint("*main")
```

We can confirm that, in fact, we're working with the same object by doing a
small experiment. Let's take a look at this example script:
```python
#!/usr/bin/env python3

import time
from pwn import *


exe = ELF("./a.out_patched")

context.binary = exe
context.terminal = ['alacritty', '-e']


def main():
    r = gdb.debug([exe.path], api=True)
    while True:
        time.sleep(1)
        try:
            print(r.gdb.magic)
        except AttributeError:
            print('magic not defined')


if __name__ == "__main__":
    main()
```

Okay now let's run it.
```
➜  dsa python solve.py
[*] '/tmp/dsa/a.out_patched'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/usr/bin/gdbserver': pid 64755
[*] running in new terminal: ['/usr/bin/gdb', '-q', '/tmp/dsa/a.out_patched', '-x', '/tmp/pwn0qtbhyhr.gdb']
magic not defined
magic not defined
magic not defined
magic not defined
```


Now we run the Python interpreter in GDB and define the magic attribute.
```python
In [1]: gdb.magic = 1234
```

It works!
```
magic not defined
magic not defined
1234
1234
1234
1234
```
