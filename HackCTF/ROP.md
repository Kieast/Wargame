# ROP

```c
kimdong@ubuntu  ~/Wargame/300~350  file rop
rop: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=44cfbcb6b7104566b4b70e843bc97c0609b7a018, not stripped

Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)

```
이번 바이너리 파일은 NX-bit가 enable되어 있고 32-bit에 libc파일이 동봉되어있다.<br>

```c
kimdong@ubuntu  ~/Wargame/300~350  ./rop
aaaaaaaaaaa
Hello, World!
```
실행시켜보면, 문자열을 입력받고 `Hello, World!`를 출력시켜주는 형태이다.<br>

```c
gef➤  disas main
Dump of assembler code for function main:
   0x08048470 <+0>:	lea    ecx,[esp+0x4]
   0x08048474 <+4>:	and    esp,0xfffffff0
   0x08048477 <+7>:	push   DWORD PTR [ecx-0x4]
   0x0804847a <+10>:	push   ebp
   0x0804847b <+11>:	mov    ebp,esp
   0x0804847d <+13>:	push   ecx
   0x0804847e <+14>:	sub    esp,0x4
   0x08048481 <+17>:	call   0x804844b <vulnerable_function>
   0x08048486 <+22>:	sub    esp,0x4
   0x08048489 <+25>:	push   0xe
   0x0804848b <+27>:	push   0x8048530
   0x08048490 <+32>:	push   0x1
   0x08048492 <+34>:	call   0x8048340 <write@plt>
   0x08048497 <+39>:	add    esp,0x10
   0x0804849a <+42>:	mov    eax,0x0
   0x0804849f <+47>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x080484a2 <+50>:	leave  
   0x080484a3 <+51>:	lea    esp,[ecx-0x4]
   0x080484a6 <+54>:	ret  

gef➤  disas vulnerable_function
Dump of assembler code for function vulnerable_function:
      0x0804844b <+0>:	push   ebp
      0x0804844c <+1>:	mov    ebp,esp
      0x0804844e <+3>:	sub    esp,0x88
      0x08048454 <+9>:	sub    esp,0x4
      0x08048457 <+12>:	push   0x100
      0x0804845c <+17>:	lea    eax,[ebp-0x88]
      0x08048462 <+23>:	push   eax
      0x08048463 <+24>:	push   0x0
      0x08048465 <+26>:	call   0x8048310 <read@plt>
      0x0804846a <+31>:	add    esp,0x10
      0x0804846d <+34>:	nop
      0x0804846e <+35>:	leave  
      0x0804846f <+36>:	ret    
   End of assembler dump.

```

main문은 간단하였고, vulnerable_function을 호출하고, 문자열을 출력해주는 형태였다.<br>

`vulnerable_function`은  `ebp-0x88`만큼 데이터를 입력받는 함수이다.<br>

따라서 bof취약점을 이용할수있다.<br>

ROP에 사용할 gadget을 찾아보자.<br>

```c
0x08048509: pop esi ; pop edi ; pop ebp ; ret  ;  (1 found)
```

write함수를 이용할것이므로, pop pop pop ret의 구조의 가젯을 구했다.<br>
