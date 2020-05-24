# Random Key

```c
kimdong@ubuntu  ~/Wargame/200~250  file random
random: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=450986f67ff81eb7b09287fc517c25f9ba89bac6, not stripped

kimdong@ubuntu  ~/Wargame/200~250  checksec random
[*] Checking for new versions of pwntools
   To disable this functionality, set the contents of /home/kimdong/.pwntools-cache-2.7/update to 'never'.
[*] You have the latest version of Pwntools (4.0.1)
[*] '/home/kimdong/Wargame/200~250/random'
   Arch:     amd64-64-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x400000)

   ```
이번 바이너리는 64-bit이고, mitigation은 NX-bit가 설정되어있다.<br>

```c
kimdong@ubuntu  ~/Wargame/200~250  ./random
============================
======= 인증 프로그램 ======
============================
Input Key : 123456
Nah...

 ```
실행시키면 문자열과 함께 사용자의 입력값을 받고, 검증한뒤에 다시 문자열을 출력해주는 형식이다.<br>

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  int v4; // [rsp+0h] [rbp-10h]
  int v5; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v6; // [rsp+8h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setbuf(_bss_start, 0LL);
  v4 = 0;
  v3 = time(0LL);
  srand(v3);
  v5 = rand();
  puts("============================");
  puts(asc_400948);
  puts("============================");
  printf("Input Key : ");
  __isoc99_scanf("%d", &v4);
  if ( v5 == v4 )
  {
    puts("Correct!");
    system("cat /home/random/flag");
    exit(0);
  }
  puts("Nah...");
  exit(0);
}
```
main문을 보면 사용자의 입력값을 특정 문자열과 비교를 하여, 맞을 시 flag를 띄워주는 형식이다.<br>

v3는 time(0)를 입력하면, 1970년 1월 1일 0시 이후 부터 현재까지 지난 시간을 '초'단위로 return시켜준다.<br>

v5는 이 return값을 srand를 통해 난수를 초기화한뒤에, rand를 통해 시간을 기반으로한 진정한 무작위 숫자가 생성되고,<br>

이를 저장한 값이다.<br>

따라서, 위와 똑같이 코딩을 하여, 서버로 전송해주면 문제가 해결가능할것 같다.<br>

c언어를 사용하여, 똑같은 환경에서 난수를 생성할수 있는 코드를 작성했다.<br>

---

## Random.c

```c

#include <stdio.h>
#include <time.h>
#include <stdlib.h>

int main()
{
        int v3;
        int flag;
        v3 = time(0);
        srand(v3);
        flag = rand();
        printf("%d\n",flag);
}

  ```
작성한 뒤에 gcc로 컴파일을 해준뒤에 다음 명령어를 통해 전송했다.<br>

 ` kimdong@ubuntu  ~/Wargame/200~250  ./Random | nc ctf.j0n9hyun.xyz 3014`<br>


```c
kimdong@ubuntu  ~/Wargame/200~250  ./random | nc ctf.j0n9hyun.xyz 3014
============================
======= 인증 프로그램 ======
============================
Input Key : Correct!
HackCTF{}
 ```

## END !
