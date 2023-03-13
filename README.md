# utctf-2023

# Looks Correct to Me

The flag checker looks right to me

oh I guess it doesn't terminate if your flag is right

[Check](https://github.com/noamgariani11/utctf-2023/blob/main/check)

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

First I used sudo chmod +x filename to be able to execute it. Than I realized from the description and using the executable it "doesn't terminate" when the flag is right, and says it "looks wrong to me :/" when it isn't the flag. Given the format utctf{flag...} if you input utflag is wouldn't terminate, but utflz would terminate. So I wrote a script that would try every possible combination and when the return code wasn't "looks wrong to me :/" than it would add that charater to the current flag and move on to the next letter. I initially set the flag to "utflag{" as it is a known value. To account for it not terminating or doing nothing I made the recvall terminate after 0.01 seconds. The process exits the infinite while loop once it reaches the end of the flag "}".

# Reading List

I created this binary to keep track of some strings that I want to read. I thought I put a CTF flag in it so I'll remember to make a problem for UTCTF, but I can't seem to find it...

strings filename | grep utflag


