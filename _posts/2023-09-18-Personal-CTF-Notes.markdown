---
layout: post
title: "My Personal CTF Notes"
date: 2023-09-18
categories: c python pwn rev ctf
---

# Introduction
These are my private notes that I used to keep for myself but I figured that there is some in my opinion cool stuff worth sharing there. I use them all the time myself!

# Running non-native binaries with Qemu
Run:
```
qemu-aarch64-static -g 2345 -L optional_library_path ./a.out
```
...and after this we can connect with gdb-multiarch through:
```
pwndbg> target remote 0.0.0.0:2345
```
However it can be super wonky. `Ctrl-c` to stop execution doesn't work, but we can instead send the sigint signal to the qemu process and then it stops execution after a `continue`. It's still buggy though, for example when we disconnect and connect GDB again after a continue, then sending sigint instead of stopping the execution, terminates the process. It's a common problem there's a 12 years old bug report: https://gdb.sourceware.narkive.com/Z1LCkr20/remote-qemu-ctrl-c-does-not-work .
Also plugins like pwndbg and gef might appear buggy cuz qemu might not provide vmmap info to GDB: https://lore.kernel.org/all/20220221030910.3203063-1-dominik.b.czarnota@gmail.com/ .

# Copying libc and ld from a Docker Container
```bash
docker run --rm -ti -v "$PWD":/host ubuntu bash # to get an ubuntu container with a mounted path to copy things out
ldd /bin/ls # to see where the libc is or whatever (in this case libc is in /lib/x86_64-linux-gnu)
cp /lib/x86_64-linux-gnu/libc.so.6 /host
```

# Papers
- [AVX Timing Side-Channel Attacks against Address Space Layout Randomization](https://arxiv.org/pdf/2304.07940.pdf)
- [Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR](https://gruss.cc/files/prefetch.pdf)
- [Blind Format Strings Attacks](https://www.sec.in.tum.de/i20/publications/blind-format-string-attacks/@@download/file/formatstring.pdf)

# Linux kernel exploitation
In case a challenge doesn't provide helper scripts there are some templates based on https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/ .
For compressing the initramfs directory:
```bash
#!/bin/sh

# try to move the exploit automatically to initramfs
gcc -o exploit -static $1
mv ./exploit ./initramfs

# compress the initramfs dir
cd initramfs
find . \
| cpio -ov --format=newc --owner=root \
| gzip -v1 > initramfs.cpio.gz
mv ./initramfs.cpio.gz ../
```

For decompressing `initramfs.cpio.gz`:
```bash
#!/bin/sh

mkdir initramfs
cd initramfs
cp ../initramfs.cpio.gz .
gunzip ./initramfs.cpio.gz
cpio -idm < ./initramfs.cpio
rm initramfs.cpio
```

For decompressing the compressed kernel image (usually called vmlinuz) use: [this](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux).

For running the kernel vm with an exposed GDB port:
```bash
#!/bin/sh

qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64,+smep,+smap \
    -kernel vmlinuz \
    -initrd initramfs.cpio.gz \
    -hdb flag.txt \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -gdb tcp::1234 \
    -no-reboot \
    -append "console=ttyS0 kaslr pti=on quiet panic=1"
```

## Links
- [Best resource for kernel exploitation introduction](https://pawnyable.cafe/)
- [Structs useful for heap exploitation](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628)
- https://github.com/ocastejon/linux-kernel-learning/blob/main/notes/slab-allocator.md
- [Linux mm notes](https://github.com/lorenzo-stoakes/linux-mm-notes)
- [Understanding paging](https://zolutal.github.io/understanding-paging/)

# More or less obscure tricks
- [Code execution with a write primitive on last libc](https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc)
- There's the `_dl_make_stack_executable` function in glibc's ld. I've never seen this used in an actual exploit but seems cool to know about nonetheless.
- `mmap` returns addresses placed close to libc (check out `house of muney` for more info).
- The read and write syscalls do not complain about being fed an invalid memory address and simply return an error. Might be useful for finding writeable memory without having a leak.
- Allegedly theres a magic race condition in one `one_gadget` (the gadget is actually in exec_comm and to find it you have to use one_gadget with `-l 1` argument). It can return a shell even though the constraints aren't met. I saw it a long ago in a ctf being used but when I tried to recreate it recently it didn't seem to work, so take this with a grain of salt and do your own research.
```c
0x10dbca posix_spawn(rsp+0x64, "/bin/sh", [rsp+0x40], 0, rsp+0x70, r9)
constraints:
  [rsp+0x70] == NULL
  [r9] == NULL || r9 == NULL
  [rsp+0x40] == NULL || (s32)[[rsp+0x40]+0x4] <= 0
 ```

# Important versions of things
- glibc-2.24 - Added check for `FILE`s vtable address.
- glibc-2.26 - Moved the `FILE`s vtable to a non-writable memory.
- glibc-2.28 - Added tcache double free check.
- glibc-2.29 - Moved the `FILE`s vtable back to a writable area.
- glibc-2.34 - Removed the ret2csu gadget.
- glibc-2.34 - `malloc` hooks removed from the API.
- Linux 2.6.23 - NULL ptr dereference mitigation
- Linux 6.2 - `commit_creds(prepare_kernel_cred(NULL));` no longer works. Now we need to pass `&init_cred` as the arg.

# Pyjails
Example payloads to reuse:
```python
(__builtins__:=__import__('code'))==(lambda:interact())()

# from https://hackmd.io/@crazyman/H1s0b1Hii
__import__('antigravity',setattr(__import__('os'),'environ',dict(BROWSER='/bin/sh -c "/readflag giveflag" #%s')))
```
Tricks that might be helpful:
- [Non-ascii identifiers get translated to ascii
  ones.](https://peps.python.org/pep-3131/)
- [You can change the encoding of the file with a comment. Changing to
  utf-7 is especially useful.](https://peps.python.org/pep-0263/)
- [Symbolic Python.](https://esolangs.org/wiki/Symbolic_Python)

# LaTeX
For simple RCE's I like [the hacktricks article](https://book.hacktricks.xyz/pentesting-web/formula-csv-doc-latex-ghostscript-injection). If it's not enough there's this very cool paper: [Are Text-Only Data Formats Safe? Or, Use This LATEX Class File to Pwn Your Computer](https://hovav.net/ucsd/dist/texhack.pdf). Also [reading binary files might be useful](https://tex.stackexchange.com/a/70636).

