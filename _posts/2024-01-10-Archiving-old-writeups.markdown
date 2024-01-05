---
layout: post
title: "Archiving My Write-Ups From Our Old, Now Removed, Wiki"
date: 2024-01-05
categories: ctf rev emulator pyjail
---

# Introduction
With the decision to nuke our team's old wiki where we sometimes put our write-ups I decided to archive my writings so it doesn't get lost in the void. Why we decided to remove it? Most of us put our write-ups on our blogs anyway and the wiki was glowing with emptiness. Why I didn't put them on my blog like I did with some other ones? Probably out of laziness, but I also didn't want to spam this blog with one or two short write-ups per ctf.

# amateursCTF 2023
## 🏴❓🇨🇹🇫 - writeup
This was a write-up written for a write-up competition post ctf where 5 writeups were given $50. The idea was very simple - because the challenge was about emojicode, let's make write it with a lot of emojis too. I was able to get $50 so hey, free money!

### Introduction 🌟
🔍🔓🔬 For this exciting reverse engineering challenge, we present to you a mind-boggling 🚩 checker! 🕵️‍♂️🔍👀 Get ready to dive into the extraordinary world of an esoteric language known as emojicode 🎩💫✨. Brace yourself, as we unveil the mysterious source code below: 📝💻👇
```
🏁 🍇
    👄🔤▶️🔤❗️🆕🔡▶️👂🏼❗️➡️input

    🆕🔠256❗️➡️ChessBattleAdvanced
    🔂griddle 📇input❗️🍇 
        🐻ChessBattleAdvanced 🔡🔢griddle❗️2❗️❗️
    🍉
    📇🔡ChessBattleAdvanced❗️❗️➡️ac7u411y.1t5.th3.inpu7.4ga1n
    ↪️📏ac7u411y.1t5.th3.inpu7.4ga1n❓▶256🍇
        😀🔤❌❌🔤❗️🚪🐇💻1❗️
    🍉

    🆕🍨🐚🔢🍆❗️➡️🖍️🆕hint
    🆕🍨hint 16❗️➡️🖍️🆕egg
    🆕🍨hint 16❗️➡️🖍️🆕bacon

    🔂i🆕⏩0 📏ac7u411y.1t5.th3.inpu7.4ga1n❓❗️🍇
        ↪️ 🔢🐽ac7u411y.1t5.th3.inpu7.4ga1n i❗️❗️➖48🙌1🍇
            🐽egg i🚮16 ❗️➡️🖍️hint
            ↪️📏hint❓ 🙌 0🍇🐻hint 0❗️🍉
            🐽hint 📏hint❓➖1 ❗️➕1➡️🐽hint 📏hint❓➖1❗️hint➡️🐽egg i🚮16❗️

            🐽bacon i➗16 ❗️➡️🖍️hint
            ↪️📏hint❓ 🙌 0🍇🐻hint 0❗️🍉
            🐽hint 📏hint❓➖1 ❗️➕1➡️🐽hint 📏hint❓➖1❗️hint➡️🐽bacon i➗16❗️
        🍉
        🙅 🍇
            🐽egg i🚮16 ❗️➡️🖍️hint
            ↪️📏hint❓▶0 🤝 🐽hint 📏hint❓➖1❗️▶0🍇🐻hint 0❗️🍉
            hint➡️🐽egg i🚮16 ❗️

            🐽bacon i➗16 ❗️➡️🖍️hint
            ↪️📏hint❓▶0 🤝 🐽hint 📏hint❓➖1❗️▶0🍇🐻hint 0❗️🍉
            hint➡️🐽bacon i➗16 ❗️
        🍉
    🍉
    🔂i🆕⏩0 16❗️🍇
        🐽egg i❗️➡️🖍️hint
        ↪️📏hint❓▶0 🤝 🐽hint 📏hint❓➖1❗️🙌0🍇🐼hint❗️🍉
        hint➡️🐽egg i❗️

        🐽bacon i❗️➡️🖍️hint
        ↪️📏hint❓▶0 🤝 🐽hint 📏hint❓➖1❗️🙌0🍇🐼hint❗️🍉
        hint➡️🐽bacon i❗️
    🍉

    🍿🍿1 1 1 2 1🍆🍿1 2 10🍆🍿2 3 2 1 2🍆🍿4 3 1 1🍆🍿2 4 4🍆🍿2 1 5 1🍆🍿2 2 1 3 2🍆🍿4 6 1 1🍆🍿1 1 2 1 2 2🍆🍿2 2 5 1🍆🍿1 1 3 5 1🍆🍿1 1 2 2 1 3🍆🍿2 1 2 3🍆🍿2 5 7🍆🍿1 2 6 1🍆🍿1 3 1 3 3🍆🍆 ➡️ chicken
    🍿🍿2 3 2 3🍆🍿4 1 2🍆🍿1 4 1 4 1🍆🍿3 3 3🍆🍿1 1 1 2 3🍆🍿1 4 5 1🍆🍿2 1 4 3🍆🍿7 1 2🍆🍿1 3 2 2 2🍆🍿4 3 2 3🍆🍿3 3 7🍆🍿1 3 3 3🍆🍿4 3 1🍆🍿2 1 2 7🍆🍿2 3 1 3 1🍆🍿3 7 1🍆🍆 ➡️ pig

    0➡️🖍️🆕the-tale-of-farmer-john-and-his-cow-bessie
    🔂i 🆕⏩0 16❗️🍇
        ↪️🐽chicken i❗️ 🙌 🐽egg i❗️🍇
            the-tale-of-farmer-john-and-his-cow-bessie ⬅️➕ 1
        🍉

        ↪️🐽pig i❗️ 🙌 🐽bacon i❗️🍇
            the-tale-of-farmer-john-and-his-cow-bessie ⬅️➕ 1
        🍉
    🍉
    💭 here's a freebie for you
    💭 😀🔡the-tale-of-farmer-john-and-his-cow-bessie❗️❗️

    ↪️🤜the-tale-of-farmer-john-and-his-cow-bessie 🙌 32🤛🍇😀🔤✅🔤❗️🍉
    🙅🍇😀🔤❌❌🔤❗️🍉
🍉
```

### Failed attempts 🔨🔥
😩 As the normal solving method seemed incredibly painful (I must admit, working with esolangs can be quite frustrating), I embarked on a quest to find a smarter way to conquer this challenge. 🤔💡
#### Searching for side-channel attacks 🔍🕵️‍♂️
🔢 Sometimes, in challenges where the flag is checked letter by letter, we can unleash the power of a simple side-channel attack. ⌛🔍🔢 By carefully observing execution time or counting executed instructions, we can determine the elusive flag. 🏴‍☠️🔍🔐 In fact, I successfully employed this technique in another CTF challenge called jvm – a delightful VM written in Java. 🎉🔍✍️ To crack it, I injected instruction counting into the bytecode, enabling me to swiftly snatch the flag. 💪🔓

🔧 For regular executables, this approach becomes a tad more challenging. Nonetheless, I've previously created a modest tool for such purposes, though nothing too fancy. It harnesses the power of perf command's instruction counting, albeit lacking absolute precision. 🛠️💻 If you're curious, you can find the tool here: https://github.com/tabun-dareka/side-channel-crackme-solver. 🌟🔬✨ For further exploration on this fascinating subject, I highly recommend Julien Voisin's article "Crackme Solving for the Lazies" from the esteemed magazine "Paged Out! #1". 📚📰
![image.png](/files/image.png)
📷👀 As depicted in the screenshot, my attempts were in vain. Surprisingly, it yielded the same outcome each time. 🤷‍♀️🖼️

#### Decompiling
🛠️ The compiler works its magic and conjures a binary. Perhaps it's readable enough? 🤔

🔢📦 The resulting binary manifests as a colossal function, boasting tens of thousands of instructions. Alas, Ghidra succumbs to freezing when attempting to decompile it. 😱❄️

🙅‍♀️ Yeah... NOPE! 🙅‍♂️

💡 I also embarked on a valiant endeavor to perform basic memory analysis with gdb, diligently setting watchpoints. However, I swiftly abandoned this idea in the face of its complexity. ⏳🔬💻

#### ChatGPT to the rescue? 💫💻
🌙🌠 Oh, one would think so. However, it regrettably spewed out nonsensical gibberish. Perhaps it's a skill issue, but truth be told, despite being hailed as the ultimate tool by many, it never quite worked its magic for me. Instead, it consistently churned out garbage and misleading information. 🚫🤷‍♂️🗑️

### The actual solution 🔐✨
😔 Sigh... it's time to embark on an adventure to learn emojicode. I won't delve into the intricate details of the process, but essentially, what I did was meticulously explore each and every emoji in the language documentation found at https://www.emojicode.org/docs/ to decipher its meaning. 📚💻🔍 While it may be a humorous language, it surprisingly boasts a multitude of features, which ironically made it more challenging to comprehend due to the lack of comprehensive documentation. 😅📖 The absence of examples proved to be the most agonizing aspect for me. However, with a little assistance from my teammate, sn0w, I successfully translated the program to sneklang. 🐍🐍 And now... BEHOLD. 🙌🐍
```python
our_input = input()
bits = ""
for byte in bytes(our_input, 'ascii'):
    bits += bin(byte)[2:]


egg = []
bacon = []
for _ in range(16):
    egg.append([])
    bacon.append([])

for i, bit in enumerate(bits):
    if bit == "1":
        # 🐽egg i🚮16 ❗️➡️🖍️hint
        hint = egg[i%16]
        # ↪️📏hint❓ 🙌 0🍇🐻hint 0❗️🍉
        if len(hint) == 0:
            hint.append(0)
        # 🐽hint 📏hint❓➖1 ❗️➕1➡️🐽hint 📏hint❓➖1❗️hint➡️🐽egg i🚮16❗️
        hint[len(hint)-1] = hint[len(hint)-1]+1
        egg[i%16] = hint

        # 🐽bacon i➗16 ❗️➡️🖍️hint
        hint = bacon[i//16]
        # ↪️📏hint❓ 🙌 0🍇🐻hint 0❗️🍉
        if len(hint) == 0:
            hint.append(0)
        # 🐽hint 📏hint❓➖1 ❗️➕1➡️🐽hint 📏hint❓➖1❗️hint➡️🐽bacon i➗16❗️
        hint[len(hint)-1] = hint[len(hint)-1]+1
        bacon[i//16] = hint
    else:
        # 🐽egg i🚮16 ❗️➡️🖍️hint
        hint = egg[i%16]
        # ↪️📏hint❓▶0 🤝 🐽hint 📏hint❓➖1❗️▶0🍇🐻hint 0❗️🍉
        if len(hint) > 0 and hint[len(hint)-1] > 0:
            hint.append(0)
        # hint➡️🐽egg i🚮16 ❗️
        egg[i%16] = hint

        # 🐽bacon i➗16 ❗️➡️🖍️hint
        hint = bacon[i//16]
        # ↪️📏hint❓▶0 🤝 🐽hint 📏hint❓➖1❗️▶0🍇🐻hint 0❗️🍉
        if len(hint) > 0 and hint[len(hint)-1] > 0:
            hint.append(0)
        # hint➡️🐽bacon i➗16 ❗️
        bacon[i//16] = hint

for i in range(16):
    # 🐽egg i❗️➡️🖍️hint
    hint = egg[i]
    # ↪️📏hint❓▶0 🤝 🐽hint 📏hint❓➖1❗️🙌0🍇🐼hint❗️🍉
    if len(hint) > 0 and hint[len(hint)-1] == 0:
        hint.pop()
    # hint➡️🐽egg i❗️
    egg[i] = hint

    # 🐽bacon i❗️➡️🖍️hint
    hint = bacon[i]
    # ↪️📏hint❓▶0 🤝 🐽hint 📏hint❓➖1❗️🙌0🍇🐼hint❗️🍉
    if len(hint) > 0 and hint[len(hint)-1] == 0:
        hint.pop()
    # hint➡️🐽bacon i❗️
    bacon[i] = hint

# 🍿🍿1 1 1 2 1🍆🍿1 2 10🍆🍿2 3 2 1 2🍆🍿4 3 1 1🍆🍿2 4 4🍆🍿2 1 5 1🍆🍿2 2 1 3 2🍆🍿4 6 1 1🍆🍿1 1 2 1 2 2🍆🍿2 2 5 1🍆🍿1 1 3 5 1🍆🍿1 1 2 2 1 3🍆🍿2 1 2 3🍆🍿2 5 7🍆🍿1 2 6 1🍆🍿1 3 1 3 3🍆🍆 ➡️ chicken
c = "1 1 1 2 1🍆🍿1 2 10🍆🍿2 3 2 1 2🍆🍿4 3 1 1🍆🍿2 4 4🍆🍿2 1 5 1🍆🍿2 2 1 3 2🍆🍿4 6 1 1🍆🍿1 1 2 1 2 2🍆🍿2 2 5 1🍆🍿1 1 3 5 1🍆🍿1 1 2 2 1 3🍆🍿2 1 2 3🍆🍿2 5 7🍆🍿1 2 6 1🍆🍿1 3 1 3 3"
chicken = []
for line in c.split("🍆🍿"):
    chicken.append([int(n) for n in line.split()])
# 🍿🍿2 3 2 3🍆🍿4 1 2🍆🍿1 4 1 4 1🍆🍿3 3 3🍆🍿1 1 1 2 3🍆🍿1 4 5 1🍆🍿2 1 4 3🍆🍿7 1 2🍆🍿1 3 2 2 2🍆🍿4 3 2 3🍆🍿3 3 7🍆🍿1 3 3 3🍆🍿4 3 1🍆🍿2 1 2 7🍆🍿2 3 1 3 1🍆🍿3 7 1🍆🍆 ➡️ pig
c = "2 3 2 3🍆🍿4 1 2🍆🍿1 4 1 4 1🍆🍿3 3 3🍆🍿1 1 1 2 3🍆🍿1 4 5 1🍆🍿2 1 4 3🍆🍿7 1 2🍆🍿1 3 2 2 2🍆🍿4 3 2 3🍆🍿3 3 7🍆🍿1 3 3 3🍆🍿4 3 1🍆🍿2 1 2 7🍆🍿2 3 1 3 1🍆🍿3 7 1"
pig = []
for line in c.split("🍆🍿"):
    pig.append([int(n) for n in line.split()])

count = 0
for i in range(16):
    if chicken[i] == egg[i]:
        count += 1
    if pig[i] == bacon[i]:
        count += 1
if count == 32:
    print("CORRECT")
else:
    print("INCORRECT")
```
💬🔢 I've added comments to provide clarity on which line corresponds to which code in the emojicode. 📝👀 Essentially, the program operates based on input's bits and performs additions on the values of the arrays, which are treated as stacks. 🔄🔢 It's worth noting that the stack nature of the arrays becomes crucial in solving the challenge, as we can deduce that the program won't access elements that appear earlier since there are no popping operations involved. 💡

To determine if the given input can lead to success, a "trivial" check is performed. As for the solution, a backtracking algorithm is implemented. 🔄🔍 Backtracking is a computer sciency way of saying: try one approach ➡️ check if it's possible to complete ➡️ if not, backtrack and try another approach. 🔄🔎 It's possible that I may have gone a bit overboard with the backtracking, but I attempted to print the values and perform the process manually. Unfortunately, my brain proved too small for the task. 😅🧠

🔎🔢 One important observation to make is that instead of directly working with characters, my program searches for the specific bits that need to be inserted. 🕵️‍♀️💡 Then, once these bits are found, we will transform them back into their corresponding characters. 🔄🔡

```python
import copy
import sys

c = "1 1 1 2 1🍆🍿1 2 10🍆🍿2 3 2 1 2🍆🍿4 3 1 1🍆🍿2 4 4🍆🍿2 1 5 1🍆🍿2 2 1 3 2🍆🍿4 6 1 1🍆🍿1 1 2 1 2 2🍆🍿2 2 5 1🍆🍿1 1 3 5 1🍆🍿1 1 2 2 1 3🍆🍿2 1 2 3🍆🍿2 5 7🍆🍿1 2 6 1🍆🍿1 3 1 3 3"
chicken = []
for line in c.split("🍆🍿"):
    chicken.append([int(n) for n in line.split()])
c = "2 3 2 3🍆🍿4 1 2🍆🍿1 4 1 4 1🍆🍿3 3 3🍆🍿1 1 1 2 3🍆🍿1 4 5 1🍆🍿2 1 4 3🍆🍿7 1 2🍆🍿1 3 2 2 2🍆🍿4 3 2 3🍆🍿3 3 7🍆🍿1 3 3 3🍆🍿4 3 1🍆🍿2 1 2 7🍆🍿2 3 1 3 1🍆🍿3 7 1"
pig = []
for line in c.split("🍆🍿"):
    pig.append([int(n) for n in line.split()])
egg = []
bacon = []
for _ in range(16):
    egg.append([])
    bacon.append([])


def check_status(i, s):

    egg_copy = copy.deepcopy(egg)
    bacon_copy = copy.deepcopy(bacon)
    for k in range(16):
        hint = egg_copy[k]
        if len(hint) > 0 and hint[len(hint)-1] == 0:
            hint.pop()
        egg_copy[k] = hint

        hint = bacon_copy[k]
        if len(hint) > 0 and hint[len(hint)-1] == 0:
            hint.pop()
        bacon_copy[k] = hint


    for chicken_line, egg_line in zip(chicken, egg_copy):
        if len(chicken_line) < len(egg_line):
            return False
        for idx, egg_element in enumerate(egg_line):
            if egg_element < chicken_line[idx] and idx != len(egg_line)-1:
                return False
            if egg_element > chicken_line[idx]:
                return False
    for pig_line, bacon_line in zip(pig, bacon_copy):
        if len(pig_line) < len(bacon_line):
            return False
        for idx, bacon_element in enumerate(bacon_line):
            if bacon_element < pig_line[idx] and idx != len(bacon_line)-1:
                return False
            if bacon_element > pig_line[idx]:
                return False
    for j in range(0, i//16):
        if bacon_copy[j] != pig[j]:
            return False
    count = 0
    for k in range(16):
        if chicken[k] == egg_copy[k]:
            count += 1
        if pig[k] == bacon_copy[k]:
            count += 1
    if count == 30:
        print('pleading')
    if count == 32:
        print(s)
        print("CORRECT")
        sys.exit()
    return True


def dfs(bit, i, s):
    global chicken
    global pig
    global egg
    global bacon
    if i > 255:
        return
    # Small optimization
    if s.endswith("0000000"):
        return
    if bit == '1':
        hint = egg[i%16]
        if len(hint) == 0:
            hint.append(0)
        hint[len(hint)-1] = hint[len(hint)-1]+1
        egg[i%16] = hint

        hint = bacon[i//16]
        if len(hint) == 0:
            hint.append(0)
        hint[len(hint)-1] = hint[len(hint)-1]+1
        bacon[i//16] = hint
        
        if check_status(i, s):
            dfs("1", i+1, s+"1")
            dfs("0", i+1, s+"0")
        hint = egg[i%16]
        hint[len(hint)-1] = hint[len(hint)-1]-1
        egg[i%16] = hint

        hint = bacon[i//16]
        hint[len(hint)-1] = hint[len(hint)-1]-1
        bacon[i//16] = hint
    else:
        hint = egg[i%16]
        a1 = False
        a2 = False
        if len(hint) > 0 and hint[len(hint)-1] > 0:
            a1 = True
            hint.append(0)
        egg[i%16] = hint

        hint = bacon[i//16]
        if len(hint) > 0 and hint[len(hint)-1] > 0:
            a2 = True
            hint.append(0)
        bacon[i//16] = hint

        if check_status(i, s):
            dfs("1", i+1, s+"1")
            dfs("0", i+1, s+"0")
        if a1:
            egg[i%16].pop()
        if a2:
            bacon[i//16].pop()

dfs("1", 0, "1")
```
🎉🎉 And behold, we have obtained our output! 🎉🎉
```
1100001110110111000011110100110010111101011110010111001110000111010100100011011110111101111101000110100111100111011111110001011001011101100110111111011101100111111001110111111101001110111011100111100011100100110010110111111101101110100111010111000111111101
```
⚠️💔 One final unpleasant aspect to note is that the challenge seems to disregard the zeroes on the left of a byte. Additionally, while all letters are represented by 7 bits, the digits occupy only 6 bits. This introduces a guessing game when parsing the input, as we need to determine the correct positions for the digits. 😕🔢
```python
In [2]: a = "1100001110110111000011110100110010111101011110010111001110000111010100100011011110111101111101000110100111100111011111110001011001011101100110111111011101100111111001
   ...: 110111111101001110111011100111100011100100110010110111111101101110100111010111000111111101"

In [3]: def tryit(a):
   ...:     s = ""
   ...:     i = 0
   ...:     j = 0
   ...:     while i < len(a):
   ...:         if j in numbers:
   ...:             s += chr(int(a[i:i+6], 2))
   ...:             i += 6
   ...:         else:
   ...:             s += chr(int(a[i:i+7], 2))
   ...:             i += 7
   ...:         j += 1
   ...:     return s
   ...:

In [4]: for i in range(20, 40):
   ...:     for j in range(i+1, 40):
   ...:         numbers = [12, i, j]
   ...:         s = tryit(a)
   ...:         if s.endswith('}'):
   ...:             print(s)
   ...:
```
🖨️🔍✨ During the process, it seems that multiple possibilities were printed, but only one of them made logical sense. 🤔📄💡
```
amateursCTF{7his_belongs_ins1de_mi5c}
```
🎉🎉 GG 😉🎮🏆


# Angstrom CTF 2023

## Obligatory
### TLDR
```python
(__builtins__:=__import__('code'))==(lambda:interact())()
```
### The Challenge
>"angstrom needs a pyjail" - kmh11

We're given a Python file and an address where the Python program is running. Our goal is to get a shell.

```python
#!/usr/local/bin/python
cod = input("sned cod: ")

if any(x not in "q(jw=_alsynxodtg)feum'zk:hivbcpr" for x in cod):
    print("bad cod")
else:
    try:
        print(eval(cod, {"__builtins__": {"__import__": __import__}}))
    except Exception as e:
        print("oop", e)
```
At the beginning we read the input, then we check the input against some letters and if all letters in the input are allowed then we pass our string to an eval. The biggest caveat of this challenge is the lack a dot, so we can't do it in the usual method of calling methods on an import and the only function given to our `eval` through globals is `__import__`. The eval function also takes an `locals` argument which we didn't overwrote so we can check if maybe there's something useful. I'll do this by adding a simple `print(locals())` at the beginning.
```
➜  Downloads head jail.py
#!/usr/local/bin/python
print(locals())
cod = input("sned cod: ")

if any(x not in "q(jw=_alsynxodtg)feum'zk:hivbcpr" for x in cod):
    print("bad cod")
else:
    try:
        print(eval(cod, {"__builtins__": {"__import__": __import__}}))
    except Exception as e:
➜  Downloads python jail.py
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x7f8ce1a1d450>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, '__file__': '/home/tabun-dareka/Downloads/jail.py', '__cached__': None}
```
Even though there's nothing useful there, we can see the `__builtins__` dunder variable there, and that's how I got this idea of overwriting it. So now let's explain why this solution works step by step.
```python
(__builtins__:=__import__('code'))==(lambda:interact())()
```
### Why `:=`?
We need to overwrite the `__builtins__` variable but the eval function in Python takes as an argument an expression not a statement. In python the `=` operator defines a statement which makes it impossible to use as a part of an expression, which btw sometimes makes some logic annoying to express. To fix it Python developers decided to add the walrus operator `:=` which serves the same purpose as normal equal operator but can be used in expressions instead.
If you're not accustomed to thinking in terms of programming language's gramma this might be confusing to you, so there are some examples to make the difference between an expression and statement clearer:
```python
# This is an if statement
if SomeExpressionThere: pass

# This is an example expression
2+2 == 4
```

Does the equal sign needs to be a statement? No, and there are more expression based languages like Rust where equal sign defines an expression, not a statement. But Python isn't one of them.

### What's `__builtins__`?
Python is full of magic variables with double underscores, also called dunders, that define how the language behaves and this variable is one of them. Usually inside of this variable we can find all the python built-in functions like `print`, `eval`, `input`, etc. that are exposed to us in the global namespace even though we didn't import anything. We can overwrite this variable so we have access to different functions in our payload like if they were built-ins. I want to import `code`, so I can get a shell with `code.interact()`.

### Why Do We Need A Lambda?
If we try the example solution without a lambda it doesn't work which might be confusing. Through some experimentation we can see that Python still uses the old `__builtins__` from before the overwrite within the context of our expression. So we somehow need to get a new context without leaving the expression. This is where out lambda will be useful.

### Getting The Flag
After we get the shell, getting the flag is trivial.
```python
>>> import os
>>> os.system('ls')
flag-a0d6b8185c3677d985e6fb346b3f88b1.txt
run
0
>>> os.system('cat flag-a0d6b8185c3677d985e6fb346b3f88b1.txt')
actf{c0uln7_g3t_1t_7o_w0rk_0n_python39_s4dge}
```

## TI
### The Challenge
> My friend sent me this town simulator. I can't seem to beat it. Can you help me?

According to `file` we're given a TI-83+ calculator program.
```
➜  angstrom file ~/Downloads/TOWN.8xp
/home/tabun-dareka/Downloads/TOWN.8xp: TI-83+ Graphing Calculator (assembly program)
```
First before trying anything I was silently hoping that maybe the flag is encoded by a byte xor but I checked the file for that in the REPL and nothing appeared, so that was an failed try. So we will be defaulting to running an emulator and continue with that.

### The Setup
I wasn't the first to look at this challenge in my team and my teammate Sn0w helped me with the initial setup, so I don't really know anything specific about it, I will just take you through the steps to get it running.

This is the emulator we used: https://github.com/CE-Programming/CEmu
This is the ROM we used (top-most one): https://tiroms.weebly.com

To send all the things into the calculator emulator go to the `Variables` tab and do it there.

![screenshot_20230427_014241.png](/screenshot_20230427_014241.png)

After that go to the `Keypad` tab and press `prgm` button to load the files.

![screenshot_20230427_002409.png](/angstrom/screenshot_20230427_002409.png)

After that we get a menu from which we can select the town executable.

![screenshot_20230427_002631.png](/files/screenshot_20230427_002631.png)

You can type letters and do everything in the calculator through the `Keypad` tab.

### Exploring The Emulator
Before doing anything it's worth to see what's there in the emulator. It turns out the emulator has a quite powerful debugging tools which we will be abusing. Memory inspection, disassembly, breakpoints, watchpoints, even saving and restoring the whole state. After playing a little bit with moving all the windows around etc., this is how my setup looked like (I changed from dark theme to light theme in KDE cuz the colors in the emulator like the dark blue in the disassembly looked horrible with a dark theme):

![screenshot_20230427_003113.png](/files/screenshot_20230427_003113.png)

### First Screen
![7.png](/files/7.png)

At the beginning the program asks us for a name. This is basically a simple crackme with a twist that it's from an calculator emulator. In the `Memory` tab we can search for the string we entered and put a watchpoint there, so it triggers a breakpoint while the password checking code is reading it. You can add the watchpoint by rightclicking the selected byte and choosing the right option.

![screenshot_20230427_003953.png](/files/screenshot_20230427_003953.png)

And surely as expected it triggers a watchpoint while comparing two strings.

![screenshot_20230427_004744.png](/files/screenshot_20230427_004744.png)

To be honest I haven't even read the assembly there but we can see that we have two pointers stored in the registers in the `CPU Status` tab. DE points to our string and HL points to some other string `CE C RELEASE`. Now when we try to type this string into the input it takes us to a second screen.

### Second Screen

![screenshot_20230427_005313.png](/files/screenshot_20230427_005313.png)

I won't show you what each npc says cuz pasting those screenshots into a markdown file gets pretty annoying, but every one of them gives you a hint related to the final password check during option one. Basically:
1. "Your pass to get in will lead you further", so the final password is somehow related to the first one.
2. "Index 5", so we're starting from the fifth index, so probably the password is related to the string "RELEASE"
3. "Alternates to end", ???, noone in our team guessed what this hint is trying to say.
4. Takes an input and mirrors it, so for example for "123" we're returned "123321"

So now during the second password we use the same trick with the watchpoints from the first password check. Now we're taken to the second password checker but this time there's no second string in the registers. By stepping a little we can see how the values in the registers change. Again I havent read almost any assembly cuz I'm too lazy for it.

![screenshot_20230427_010344.png](/files/screenshot_20230427_010344.png)

We can observe our letter being loaded into the `a` register, then some other letter being loaded into the `l` register, and then they are compared. So we can make an obvious guess that the password is loaded into the l register. We can put a breakpoint at
```
D1AD9C     BD            cp a,l
```
and read the password letter by letter. Boom! We got the password: "RLAE".
After putting it in we get a flag but it appears corrupted. :/

![aaaaa.png](/files/aaaaa.png)

Now I made just an educated guess based on the hints and instead typed "RLAEEALR" and we got the full flag: `actf{e4sy_80_4ss3embIy7}`.

