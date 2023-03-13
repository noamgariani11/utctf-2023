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

Flag: ```utflag{L0c4l1z3d_Ch1ck3n_M0d1f1c4t10N_g8h91b3h89}```

# Reading List

I created this binary to keep track of some strings that I want to read. I thought I put a CTF flag in it so I'll remember to make a problem for UTCTF, but I can't seem to find it...

[readingList](https://github.com/noamgariani11/utctf-2023/blob/main/readingList)

strings filename | grep utflag

Flag: ```utflag{string_theory_is_a_cosmological_theory_based_on_the_existence_of_cosmic_strings}```

# What Time is It

Super Secure Company's database was recently breached. One of the employees self reported a potential phishing event that could be related. Unfortunately, our Linux email server does not report receiving any emails on March 2, 2023. Can you identify when this email was actually sent? The flag format is utflag{MM/DD/YYYY-HH:MM} in UTC time.

phipshing.eml file

In the internet headers of the email which could be found with cat or in outlook then properties there was the boundry.

![image](https://user-images.githubusercontent.com/91398631/224591833-aa61dfd3-9b18-4677-9df9-6af666879c28.png)

00000000000093882205f60cdcdb
000000000000 938822 05f60cdcdb
938822 05f60cdc db
05f60cdc 938822
05f60cdc938822 to decimal 
1677909984249890
first 13 digits - > 1677909984249
than convert from epoch to a human-readable date
Saturday, March 4, 2023 6:06:24.249 AM in GMT

GMT and UTC are the same.

Flag: ```utflag{03/04/2023-06:06}```

