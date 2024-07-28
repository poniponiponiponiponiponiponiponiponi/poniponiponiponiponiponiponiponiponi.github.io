---
permalink: /about/software
---

# Software I use and why

Warning! Opinions below.

## Emacs vs Vim (Vim, Neovim, Vi, Ed...)
Emacs. However I'm not an elitist and I dont believe Emacs is better
in any technical way. I just like the software.
### Keybindings
I even prefer the keybindings over Vim, I'm not huge on modal editing
like the whole internet seems to be. The constant switching between
normal mode and insert mode seems very annoying. In a way Vim users
are for me like people who use Caps Lock to capitalize their letters
instead of the superior shift button. There are the jokes about the
Emacs pinky or horrible Emacs' shortcuts however after rebinding
Caps Lock to Ctrl writing is very pleasant for me.
### The language
Lisp is a language that I like and seems really cool *in theory* but
outside of Emacs I don't really have any use for it. I'm writing a
quick and dirty ad-hoc program? Python. Writing exploits? C and
Python. I want to poke at some API or really any task that is good
with dynamic typing? Python. I want to write software with good static
typing that is like a pyramid, very solid but maybe a little stiff?
Rust. So Emacs fullfils the need of writing Lisp inside of me. Vim has
Vimscript which everyone and their mother seems to hate and Lua thanks
to Neovim, which I'm not a big fan of either. It's a fine language but
it doesn't do anything for me, you know. I think the idea of
representing everything as a table/tree/whatever is clever. I said to
myself that I'm not gonna mention the indexing from one.
### Config files
Topic a little related to the languages but not fully. It's also
related to how different plugins/packages in the ecosystem handle
configuration. This may say more about myself but when I used Neovim
in the past my config always always ended up being really messy as all
the plugins I used like LSP support required me to paste a big bulk of
code. I never felt like I understood all the lines in my config. In
Emacs I somehow ended with a **two times** smaller config with about
the same functionality (is some ways more, in other less). I almost
want to say three times but I don't have the numbers anymore and I
don't want to exaggarate. My config feels more elegant with about the
same amount of "care" put into it.
### Plugins
For me plugins in both editors are basically the same. All I need is a
LSP client (for which I use Eglot, which is built-in) and Tree-sitter
(which is also built-in). The rest is just sugar on top of it. Some
people will mention Org-mode or Magit as the Emacs' killer features
but I don't use them in any way that wouldn't be possible with some
Vim plugins like Vimwiki or lazygit. Honestly I even think that Neovim
is winning in the plugin race. The editor is more popular, there are
many more people writing Lua plugins and reporting bugs than there are
Lisp hackers writing Emacs macros.
### The bad things about Emacs
- No perfect highlight column at cursor position. The best extension I
  found was [this one](https://codeberg.org/akib/emacs-hl-column) but
  it still wasn't interacting properly with company-mode, it sometimes
  pushed the first completion suggestion forward, and some other
  modes.
- No proper dap-mode. Well there's the dap-mode package but it
  requires you to use lsp-mode which I don't like and I don't want to
  be locked in that ecosystem.
- It can feel quite slow on some occasions. It feels great for most of
  the time but there are cases where you can feel the garbage
  collector. You can feel the gap buffer. You can feel the one thread.
- And some more things you could mention. The community being small.
  Some dead/junky packages. Startup times. I can't think of anything
  else to be honest.
### ... vs Helix
I like the idea of Helix: having a Vim-like editor with human out of
the box experience (and no, I'm not a big fan of Vim or Emacs
distributions like Doom Emacs). I gain nothing from having a huge
config file. However I don't trust the developers and the work being
done on Helix is just too slow (which is understandable, this is an
open-source project done without much in any profit, yada,
yada). There are still [some problems with syntax highlighting that
haven't been worked on for
years](https://github.com/helix-editor/helix/issues/1151 ) which I
consider to be basic as far as using the editor goes. Still no plugin
system in sight which I consider essential.

### ... vs any other editor
At the point of writing this I never really used anything outside of
Vim, Emacs and Helix. I used a little bit of IntelliJ IDEA for a uni
group project but I wasn't impressed. When I started learning
programming it was Python with the built-in IDLE editor and after that
somehow I moved straight to Vim. I prefer to use true FOSS software
when I have the choice but if for example a job I'm in will require to
use VSCode for whatever reason I will not complain (probably!). The
only editors I despise is anything from JetBrains and alikes for the
predatory tactic of selling the same editor multiple times for every
language they decide to support. Imagine if Adobe started selling
different program for every file format!

## Shell
Firstly I'm not a fan of Zsh because the defaults there are as bad as
it is possible to make them. Due to this I used fish in the past but
now we have the drawback of having to use a shell language you
probably don't want to touch cuz you won't see it anywhere else
anyway, even if it's better than Bash (especially since I rarely write
shell scripts to begin with). That's why nowadays I mostly use Eshell
with Eat as a terminal emulator inside of Emacs. The shell has nice
integration with Emacs (duh), it uses the completion package of your
choice by default, etc. I also use Bash in the TTY because that's the
default.

## DEs vs WMs
Even though I use i3 I believe that tiling window managers are hugely
overrated for most people use-cases and they use it only because
either their favourite internet celebrity uses them or their friend
group does so. The only reason I use i3 is because I want to have an
easily configurable setup, where I have everything in one file I can
copy around. I don't think there's much speed to be gained from
switching windows a little faster. I can't think of a case where I
have more than 3 windows open (Emacs, Firefox and Ghidra) that I want
to swap around at the same time. "Alt-tabbing" is more than enough for
this. I guess I use Emacs as my terminal multiplexer and if somebody
doesn't want to use tmux then using a tiling window manager might be
helpful.

## Programming languages
My two main programming languages are Python and Rust. Like I stated
above in the Emacs section Python is my goto language for anything
where dynamic typing is king. Why not a Lisp? Lisps tend to be a
little dead and realistically in the modern world, where [programming
stopped being like magic and started being more like
science](http://lambda-the-ultimate.org/node/5335), where we poke at
different libraries and see what happens, we want our language to be
well supported with a lot libraries, cli tools and other
stuff. Overall I really like Python, the only thing that I hate is
[the lack of multistatement
lambdas](https://lwn.net/Articles/964839/). When it comes to
statically typed languages Rust is my favourite. Everything about it
just clicks for me. The ADTs. The pattern matching. The explicitness
of the language (compared to C++ which is a very implicit language in
a lot of ways. To be precise about what I mean - I don't talk about
implicit type conversions, though that's part of it, what I mean is
stuff more like how we don't know if something is a "pointer"
(reference) by how it's used until we look at the function signature,
all the functions that are implicitly used and created that are hard
to predict until you really KNOW the rules, etc.). The
functional-style programming combined with low-level concepts. All of
the CLI-centric tooling. Forgive me for getting passionate but I think
it's a lovely language. I also use C though nowadays more and more
rarely. I use it for exploit dev sometimes, when I just need to do
some syscalls, and when I feel like doing some pointer fuckery. What I
like about C is how well it maps to assembly like no other language.
I heard once an argument that it's not true because of all the
optimizations and while it might be true in theory, in practice
there's a difference between theory and practice. If you ever tried to
reverse engineer compiled programs you know how much easier it is to
do so with a C program than with any other language.

For debugging I use ipdb and gdb.

## X11 vs Wayland
I have an AMD GPU and I still use Xorg. I tried using Wayland with
Sway and it felt like torturing myself. I'm gonna give Wayland an
another try but not in the next few years. So what were my problems?
There were many and I'm sure most of them have a fix but as a user I
live by the philosophy of the least resistance - I'm gonna use the
software that causes the least amount of friction and allows me to
focus on what I want to in the current moment. Some examples:
- There was some forced VSync kind of problem. All video games that I
  wanted to play that are input sensitive were unplayable on Sway.
  Even though VSync was turned off in the game settings I had huge
  input lag in osu! and Counter Strike that wasn't present in Xorg.
- Pixelated/blurry (at this point I dont remember to be honest, maybe
  both depending on the scale) scaling of things that weren't made for
  Wayland. I have a 3K display in my laptop so scaling is
  necessary. It was for example when using Ghidra.
- Push2talk not working on Discord without a workaround.

And all those problems for what? I heard multiple monitor setups work
better on Wayland. Too bad I use only one.

## Linux distributions
I don't have any hot takes when It comes Linux distributions. Honestly
I'm fine with anything as long as it doesn't get in my way. I prefer
Systemd distros because that's what I'm used to, it always worked fine
and was easy to diagnose with journalctl (some of the arguments
against Systemd seem to be bad faith). Currently I'm using Arch but
I'm planning on going back to Fedora. I tried Guix for a day but after
not being able to install everything I wanted I gave up. Maybe I'll
give NixOS a shot in the future (probably not, just like Guix it seems
like one of those things that you love the idea of, however using it
as a desktop will be on top of the pain hierarchy).
