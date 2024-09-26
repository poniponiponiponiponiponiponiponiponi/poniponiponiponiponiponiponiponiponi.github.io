---
permalink: /about/software
---

# Software I use and why

Warning! Opinions below.

## Emacs vs Vim (Vim, Neovim, Vi, Ed, ...)
[Emacs](https://youtu.be/V3QF1uAvbkU)! That said I'm not an elitist
and I don't believe Emacs is better in any empirical way. I just like
the program.
### The language
Lisp is a language that I like and seems really cool *in theory* but
outside of Emacs I don't really have any use for it. I'm writing a
quick and dirty ad-hoc program? Python. Writing exploits? C and
Python. I want to poke at some API or really any task that is good
with dynamic typing? Python. I want to write software with good static
typing that is like a pyramid, very solid but maybe a little stiff?
Rust. Things that run in the browser? JavaScript. So Emacs fullfils
the need of writing Lisp inside of me. Vim has Vimscript which
everyone and their mother seems to hate and Lua thanks to Neovim,
which I'm not a big fan of either. It's a fine language but it doesn't
ignite that spark inside of me, you know. I think the idea of
representing everything as a table/tree/whatever you wanna call it is
clever. I said to myself that I'm not gonna mention the indexing from
one because it's a very surface level thing. ~~And I failed miserably.~~
### Config files
Topic a little related to the languages but not fully. It's also
related to how different plugins/packages in the ecosystem handle
configuration. This may say more about myself but when I used Neovim
in the past my config always ended up being really messy as all the
plugins I used, like LSP support, required me to paste a big bulk of
code in the config file. I never felt like I understood all the lines,
at least without putting effort into it. In Emacs I somehow ended with
a **two times** smaller config with about the same functionality (is
some ways more, in other less). I almost want to say three times but I
don't have the numbers anymore and I don't want to exaggarate. My
config feels more elegant with about the same amount of "care" put
into it.
### Keybindings
I even prefer the keybindings over Vim! I'm not huge on modal editing
like the whole internet seems to be. The constant switching between
normal mode and insert mode is very annoying for me. In a way Vim
users seem to me like people who use Caps Lock to capitalize their
letters instead of the superior shift button. There are the jokes
about the Emacs pinky or horrible Emacs' shortcuts however after
rebinding Caps Lock to Ctrl writing is very pleasant.
### Plugins/packages
For me plugins in both editors are basically the same. All I need is a
LSP client (for which I use Eglot, which is built-in) and Tree-sitter
(which is also built-in). The rest is just sugar on top of it. Some
people will mention Org-mode or Magit as the Emacs' killer features
but I don't use them in any way that wouldn't be possible with some
Vim plugins like Vimwiki or lazygit. Honestly I even think that Neovim
is overall winning in the plugin race. The editor is more popular,
there are many more people writing Lua plugins and reporting bugs than
there are Lisp hackers writing Emacs macros.
### The bad things about Emacs
- No proper dap-mode. Well there's the dap-mode package but it
  requires you to use lsp-mode which I don't like and I don't want to
  be locked in that ecosystem.
- It can be quite slow on some occasions. It feels great for most of
  the time but there are cases where you can feel the garbage
  collector. You can feel the gap buffer. You can feel the one thread.
- And some other things you could mention. The community being small.
  Some dead/junky packages. Startup times. I can't think of anything
  else to be honest.


### ... vs Helix
I like the idea of Helix: having a Vim-like editor with out of the box
human experience (and no, I'm not a big fan of Vim/Emacs distributions
like Doom Emacs either, but that's an another topic). I gain nothing
from having a huge config file. However I don't trust the developers
and the work being done on Helix is just too slow (which is
understandable, this is an open-source project done without much if
any profit, yada, yada). There are still [some problems with syntax
highlighting that haven't been worked on for
years](https://github.com/helix-editor/helix/issues/1151) which I
consider to be basic as far as using the editor goes. Still no plugin
system in sight which I consider essential.

### ... vs any other editor
At the point of writing this I never really used anything outside of
Vim, Emacs and Helix. I used a little bit of IntelliJ IDEA for a uni
group project but I wasn't impressed. When I started learning
programming it was Python with the built-in IDLE editor and after that
somehow I moved straight to Vim. I prefer to use true FOSS software
when I have the choice but if for example a job I'm in will require me
to use VSCode for whatever reason I will not complain (probably!). The
only editors I despise on an ideological level is anything from
JetBrains and alikes for the predatory tactic of selling the same
editor multiple times for every language they decide to support.
Imagine if Adobe started selling a different program for every file
format!

## Shell
Firstly I'm not a fan of Zsh because the defaults there are as bad as
it is possible to make them. Due to this I used fish in the past but
now we have the drawback of having to use a shell language you
probably don't want to touch cuz you won't see it anywhere else
anyway, even if it's a little better than Bash (especially since I
rarely write shell scripts to begin with). That's why nowadays I
mostly use Eshell with Eat as a terminal emulator inside of Emacs. The
shell has nice integration with Emacs (duh), it uses the completion
package of your choice by default, etc. I also use Bash in the TTY
because that's the default.

## DEs vs WMs
Even though I use i3 myself I believe that tiling window managers are
hugely overrated for most people's use-cases (It doesn't mean they
aren't good! Just that their value is overestimated.) and they only
use them because either their favourite internet celebrity uses them
or their friend group does so. The reason I use i3 is because I want
to have an easily configurable setup, where you have everything in one
file you can copy around. I don't think there's much speed to be
gained from switching windows a little faster. I can't think of a case
where I have more than 3 windows open (Emacs, Firefox and Ghidra) that
I want to swap around at the same time. "Alt-tabbing" is more than
enough for this. I guess I use Emacs as my terminal multiplexer and if
somebody doesn't want to use tmux then using a tiling window manager
might be helpful.

## Programming languages
My two main programming languages are Python and Rust. Like I stated
above in the Emacs section Python is my goto language for anything
where dynamic typing is king. Why not a Lisp? Lisps tend to be a
little dead and realistically in the modern world, where [programming
stopped being like magic and started being more like
science](http://lambda-the-ultimate.org/node/5335), where we poke at
different libraries and see what happens, we want our language to be
well supported with a lot libraries, cli tools and other stuff. That
said overall I really like Python, the only thing that I hate about it
is [the lack of multistatement
lambdas](https://lwn.net/Articles/964839/). In theory there's a
[Python Lisp dialect](https://hylang.org/), kinda like Clojure but
less serious, and it's a really cool project however just using Python
is the more pragmantic choice. When it comes to statically typed
languages Rust is my favourite. Everything about it just clicks for
me. The ADTs. The pattern matching. The functional-style programming
combined with low-level concepts. All of the CLI-centric tooling. The
explicitness of the language (compared to C++ which is a very implicit
language in a lot of ways. To be precise about what I mean - I don't
talk about implicit type conversions, though that's part of it, what I
mean is stuff more like how we don't know if something is a "pointer"
(reference) by how it's used until we look at the function signature,
all the functions that are implicitly used and created that are hard
to predict until you really KNOW the rules, the fact that you can
never know for sure if a copy is expensive or not, etc.). Forgive me
for getting passionate but I think it's a lovely language. I also use
C, though nowadays more and more rarely. I use it sometimes for
exploit dev, when I just need to do some syscalls and call it a day,
or when I feel like doing some pointer fuckery. What I like about C is
how well it maps to assembly like no other language. I heard once an
argument that it's not true because of all the optimizations and while
it might be true in theory, in practice there's a difference between
theory and practice. If you ever tried to reverse engineer compiled
programs you know how much easier it is to do so with a C program than
with any other language.

For debugging I use gdb and ipdb.

## X11 vs Wayland
I have an AMD GPU and I still use X11. I tried using Wayland with Sway
and it felt like torturing myself. I'm gonna give Wayland an another
try but not in the next few years. So what were my problems? There
were some and I'm sure most of them have a fix but as a user I live by
the philosophy of the least resistance - I'm gonna use the software
that causes the least amount of friction and allows me to focus on
what I want to in the current moment. Some examples:
- ~~There was some forced VSync kind of problem. All video games that
  I wanted to play that are input sensitive were unplayable on Sway.
  Even though VSync was turned off in the game settings I had huge
  input lag in osu! and Counter Strike that wasn't present in X11.~~
  Seems like this issue is fixed with the implementation of a [tearing
  protocol](https://github.com/swaywm/sway/issues/7811) but it still
  isn't implemented everywhere.
- Fullscreen in video games behaved weirdly.
- Pixelated/blurry (at this point I dont remember to be honest, maybe
  both depending on the scale) scaling of things that weren't made for
  Wayland. I have a 3k display in my laptop so scaling is
  necessary. It was present for example when using Ghidra.
- Push2talk not working on Discord without a workaround. Not hard to
  work around it but it's better when things just work. ;)
  
And all those problems for what? I heard multiple monitor setups work
better on Wayland. Too bad I use only one.

## Linux distributions
I don't have any 'hot takes' when It comes Linux
distributions. Honestly I'm fine with anything as long as it doesn't
get in my way. I prefer Systemd distros because that's what I'm used
to, it always worked fine and was easy to diagnose with journalctl
(some of the arguments against Systemd seem to be bad
faith). Currently I'm using Arch. In the past I used Fedora 38 (or was
it 37?) on my laptop and Fedora 40 on my desktop PC but there were
always some small problems that made me give up on using Fedora as a
daily driver. It seems like not a lot of people use Fedora on a
desktop, at least I've only met one person. For example the PCSX2
package at the time of writing is by default unsuable beyond a simple
launch. First of all for it's a 32-bit package for some
reason. Secondly, the SPU2 plugin is not found so we can't even
complete the initial setup. After a little debugging we can see it
happens because we don't have a 32-bit version of libjack.so.0 and the
plugin needs it.

```shell
[poni@Asuka /usr/lib/games/pcsx2]$ file libspu2x-2.0.0.so
libspu2x-2.0.0.so: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, BuildID[sha1]=ecc8471906cda77ab15e125bc18ad4160f5ad928, stripped
[poni@Asuka /usr/lib/games/pcsx2]$ ldd libspu2x-2.0.0.so | rg "not found"
	libjack.so.0 => not found
```

So to fix it we need to `sudo dnf install
jack-audio-connection-kit.i686`. I also encountered some weird Wine
issues like a random obscure game crashing on a mov instruction with a
memory address that doesn't exist, even though it worked fine on
Arch. For the usual complains dnf is slower than it should be,
especially after adding some
[copr](https://copr.fedorainfracloud.org/) repos. I still like Fedora
as a server though. When it comes to more obscure distros, I tried
Guix for a day but after not being able to install everything I wanted
I gave up. Maybe I'll give NixOS a shot in the future (probably not,
just like Guix it seems like one of those things that you love the
idea of, however using it as a daily driver will be on the top of the
pain hierarchy).
