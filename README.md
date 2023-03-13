# utctf-2023

# Looks Correct to Me

**Problem:** <br>
The flag checker looks right to me

oh I guess it doesn't terminate if your flag is right

[Check](https://github.com/noamgariani11/utctf-2023/blob/main/check)

**Solution:** <br>
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

**Problem:** <br>
I created this binary to keep track of some strings that I want to read. I thought I put a CTF flag in it so I'll remember to make a problem for UTCTF, but I can't seem to find it...

[readingList](https://github.com/noamgariani11/utctf-2023/blob/main/readingList)

**Solution:** <br>
strings filename | grep utflag

Flag: ```utflag{string_theory_is_a_cosmological_theory_based_on_the_existence_of_cosmic_strings}```

# What Time is It

**Problem:** <br>
Super Secure Company's database was recently breached. One of the employees self reported a potential phishing event that could be related. Unfortunately, our Linux email server does not report receiving any emails on March 2, 2023. Can you identify when this email was actually sent? The flag format is utflag{MM/DD/YYYY-HH:MM} in UTC time.

[phipshing.eml](https://github.com/noamgariani11/utctf-2023/blob/main/phishing.eml)

**Solution:** <br>
In the internet headers of the email which could be found with cat or in outlook then properties there was the boundry.

![image](https://user-images.githubusercontent.com/91398631/224591833-aa61dfd3-9b18-4677-9df9-6af666879c28.png)

00000000000093882205f60cdcdb <br>
000000000000 938822 05f60cdcdb <br>
938822 05f60cdc db <br>
05f60cdc 938822 <br>
05f60cdc938822 Hex value <br>
1677909984249890 Converted Hex to Decimal value<br>
First 13 digits - > 1677909984249 <br>
Than convert from epoch to a human-readable date <br>
Saturday, March 4, 2023 6:06:24.249 AM in GMT

GMT and UTC are the same.

Flag: ```utflag{03/04/2023-06:06}```

# A tribute to Bataille

**Problem:** <br>
Confess your sins! http://guppy.utctf.live:5321

**Solution:** <br>
This is the site: <br>
![image](https://user-images.githubusercontent.com/91398631/224592503-4d1be224-b683-41c0-a483-48ca88780621.png) <br>
![image](https://user-images.githubusercontent.com/91398631/224592531-3ff2a0ee-073e-4f04-aa18-a7efd240099b.png)

If you open the image in a new tab you see that it has this path ```/images/img2.png ``` if you go to ```/images/img1.png ``` you see the code.

![image](https://user-images.githubusercontent.com/91398631/224592655-a4942196-7e92-46d3-8959-079bd3ba053f.png)

This is the SQL Injection: ```"); SELECT * FROM confessions;--```

Flag: ```utflag{thanks_for_confessing_your_sins}```

# A Network Problem - Part 1

**Problem:** <br>
There are some interesting ports open on betta.utctf.live, particularly port 8080.

betta.utctf.live:8080

**Solution:** <br>
```nc betta.utctf.live 8080```

Flag: ```utflag{meh-netcats-cooler}```

# Insanity Check Redux

**Problem:** <br>
Note: carl-bot is out of scope. We use it for reaction roles in the rules channel. Please do not attack carl-bot.

Join our CTF discord server (https://discord.gg/uY5mVEAAVc). There's a flag there, but you'll have to work for it.

**Solution:** <br>
At the time I did this CTF there wasn't much messages but the way I thought of it is it could only be from Admins and it could only be released on or before the CTF started. I didn't think it would be from a normal competitor or released in the middle of the CTF and these assumptions made the possibilities for this challenge much less. At the time there were three images from admins that met these constraints so I downloaded all of the images and ran binwalk and zsteg -a with nothing coming up. I think ran steghide extract with the filename as the password and the third image of a duck gave the flag.

![image](https://user-images.githubusercontent.com/91398631/224594760-ca0feb13-97ab-4282-83a8-d5e940302d06.png)

I didn't find it that bad, but that image of a duck and many more from admins were posted later on in the discord. I can see how this drove some people insane if they were checking everything. 

Flag: ```utflag{again_and_again_and_again}```
