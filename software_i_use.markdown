---
title: About
permalink: /about/software
---

Warning! Opinions below.

# Emacs vs Vim (Vim, Neovim, Vi, Ed...)
Emacs. I'm not an elitist and I dont believe Emacs is better in any
technical way. I just like the software.
## Keybindings
I even prefer the keybindings over Vim, I'm not huge on modal editing
like the whole internet seems to be. The constant switching between
normal mode and insert mode seems very annoying to me. In a way Vim
users are for me like people who use caps-lock to capitalize their
words instead of the superior shift button. There are the jokes of the
emacs pinky or horrible emacs shortcuts however after rebinding
caps-lock to ctrl writing is very pleasant for me.
## The language
Lisp is a language that I like and seems really cool *in theory* but
outside of Emacs I don't really have any use for it. I'm writing a
quick and dirty ad-hoc program? Python. Writing exploits? C and
Python. I want to poke at some API or really any task that is good
with dynamic typing? Python. I want to write software with good static
typing that is like a pyramid, very solid but maybe a little stiff?
Rust. So Emacs fullfils the need of writing Lisp inside of me. Vim has
Vimscript which everyone and their mother seems to hate and Lua thanks
to neovim, which I'm not a big fan of either. It's a fine language but
it doesn't do anything for me, you know. I think the idea of
representing everything as a table/tree/whatever is clever. I said to
myself that I'm not gonna mention the indexing from one.
## Config files
Topic a little related to the languages but not fully. It's also
related to how different plugins in the ecosystem handle
configuration. When I tried using Neovim my config ended up as
hundreds of copied Lua configuration lines from github. This may say
more about myself but I always ended up with a really messy config as
all the plugins for LSP etc. I used required me to paste a big bulk of
code. I never felt like I understood all the lines in my config. In
Emacs I somehow ended with a **two times** smaller config with about
the same functionality (is some ways more, in other less). I almost
want to say three times but I don't have the numbers anymore and I
don't want to exaggarate. My config feels more elegant with about the
same work put into it.
## Plugins
For me plugins in both editors are basically the same. All I need is
an LSP client (for which I use eglot) and treesitter (which is
built-in in Emacs). The rest is just sugar on top of it. Some people
will mention org-mode or magit as Emacs' killer features but I don't
use them in any way that wouldn't be possible with some Vim
plugins. Honestly I think Neovim is winning in the plugin race. The
editor is more popular, there are much more people writing Lua plugins
and reporting bugs on GitHub currently than there are Lisp hackers
writing Emacs macros.
## The bad things about Emacs
- There's no perfect plugin for indentation guides. The best one by
  far is highlight-indent-guides but it still leaves gaps between
  empty lines which is rather ugly and distracting. Especially for a
  functionality that's a nobrainer in other
  editors. Highlight-Indentation-for-Emacs has an experimental feature
  that tries to fix it but it was very buggy. Sometimes it was
  flickering sometimes the lines didn't show up after scrolling.
- No proper highlight column at cursor position, which could be used
  as a workaround for the lack of nice looking indentation guides.
  The best extension was https://codeberg.org/akib/emacs-hl-column but
  it still wasn't interacting properly with company-mode and it
  sometimes pushed the first completion suggestion forward.
- No proper dap-mode. Well there's the dap-mode plugin but it requires
  you to use lsp-mode which I don't like I don't want to be locked in
  that ecosystem.
- It is quite slow. It feels great for most of the time but there are
  cases where you can feel the garbage collector. You can feel the gap
  buffer. You can feel the one thread.
- And some more things you could mention. The community being small.
  Some dead/junky plugins. Startup times. I can't think of anything
  more to be honest.
## ... vs Helix
I like the idea of Helix: having a Vim-like editor with human out of
the box experience. I like that. I gain nothing from having a huge
config file. However I don't trust the developers and the work being
done on it is just too slow (which is understandable, this is an
open-source project done without much profit, yada, yada). There are
still some problems with for syntax highlighting that haven't been
worked on for years (https://github.com/helix-editor/helix/issues/1151
) which I consider to be basic as far as using the editor goes. Still
no plugin system in sight which I consider essential.

## ... vs any other editor
At the point of writing this I never really used anything outside of
Vim, Emacs and Helix. I used a little bit of IntelliJ IDEA for a uni
group project but I wasn't impressed. When I started learning
programming in Python it was the built-in IDLE editor and after that I
moved straight to Vim. I prefer to use true FOSS software when I have
the choice but if for example the work I'm in will require me to use
VSCode for whatever reason I will not complain (probably!). The only
editors I really despise is anything from JetBrains for the predatory
tactic of selling the same editor multiple times for every language
they decide to support.

# DEs vs WMs
Even though I use i3 I believe that tiling window managers are hugely
overrated for most people use-cases and they use it only because
either their favourite e-celebrity uses WMs or their friend group does
so. The only reason I use i3 is because I want to have an easily
configurable setup, where I have everything in one file I can copy
around. I don't think there's much speed to be gained from switching
windows a little faster. I can't think of a case where I have more
than 3 windows (Emacs, Firefox and Ghidra) I want to swap around at
the same time. "Alt-tabbing" is more than enough for this. I guess I
use Emacs as my terminal multiplexer and if somebody doesn't want to
use tmux then using a tiling window manager might be helpful.

# Programming languages
My two main programming languages are Python and Rust. Like I stated
above in the Emacs section Python is my goto language for anything
where dynamic typing is king. Why not a Lisp? Lisps tend to be a
little dead and realistically in the modern world, where programming
stopped being like magic and started being more like science, where we
poke at different libraries and see what happens, we want our language
to be well supported with a lot libraries and stuff. Overall I really
like the language, the only thing that I hate is the lack of
multistatement lambdas. When it comes to statically typed languages
Rust is my favourite. Everything about it just clicks for me. The
ADTs. The pattern matching. The explicitness of the language (compared
to C++ which is a very implicit language in a lot of ways). The
functional-style programming combined with low-level concepts. All of
the CLI-centric tooling. Forgive me for getting passionate but I
really think it's a lovely language. For debugging I use ipdb and gdb.

# X11 vs Wayland
I have an amd GPU and I still use Xorg. I tried using Sway with
Wayland and it felt like torturing myself. I'm gonna give Wayland an
other try but not in the next few years. So what was my problem?
There were many and I'm sure most of them have a fix but as a user I
live by the philosophy of least resistance - I'm gonna use the
software that causes the least amount of friction and allows me to
focus on what I want to in the current moment. Some examples:
- There was some forced vsync kind of problem. All video games that I
  wanted to play that are input sensitive were unplayable on Sway.
  Even though vsync was turned off in the settings I had a huge input
  lag in osu! and Counter Strike that wasn't present in Xorg.
- Pixelated/blurry (at this point I dont remember to be honest, maybe
  both depending on the scale) scaling. I have a 3K display in my
  laptop so scaling is necessary. Precisely it was when using Ghidra.
- Push2talk not working on Discord without a workaround.  And all
those problems for what? I heard multiple monitor setups work better
on Wayland. Too bad I use only one monitor.

# Linux distributions
I don't have any hot takes when It comes Linux distros. Honestly I'm
fine with anything as long as it doesn't get in my way. I prefer
systemd distros because that's what I'm used to and it always worked
fine for me (some of the arguments against systemd seem to be bad
faith in my opinion). Currently I'm using Arch but I'm planning on
going back to Fedora. I tried using Guix for a day but after not being
able to install everything I wanted I gave up. Maybe I'll give NixOS a
shot in the future.
