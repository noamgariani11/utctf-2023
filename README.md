# utctf-2023

# Looks Correct to Me

The flag checker looks right to me

oh I guess it doesn't terminate if your flag is right

```
#!/usr/bin/env python

from pwn import *
import pwn
from string import printable

context.log_level = "critical"

elf = pwn.ELF("./check")

flag = "utflag{"

while True:
    for i in printable:
        p = elf.process()
        payload = "".join(flag) + i
        p.recvuntil(b"flag!")
        p.sendline(payload)
        response = p.recvall(timeout=0.01).decode("latin-1")
        # print(response)
        if(response != "\nlooks wrong to me :/\n"):
            flag += i
            break
    print(flag)
    if(flag[-1] == "}"):
        break
```  
