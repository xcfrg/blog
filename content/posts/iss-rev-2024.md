---
author: "fastcall"
title: "ISSessions Espionage CTF 2024 RE challenge writeups"
date: "2024-02-05"
description: "the rev."
summary: "Write-ups for all the reverse engineering challenges in Espionage CTF 2024."
tags: ["re", "ctf"]
categories: ["writeups"]
ShowToc: true
draft: false
---

Here are my writeups for all the reverse engineering challenges in Espionage CTF 2024. I managed to get first blood on all of the RE challenges except for ScrambledSquares.

UofTCTF Members:

- \_\_fastcall (me): rev
- drec: pwn
- Tyler\_: forensics and osint
- SteakEnthusiast: web

**NOTE: All code in this writeup has been beautified manually for your reading pleasure. It may not represent the exact disassembly, but it does represent the semantics of the code.**

## Coin Hunt (15 points)

This challenge gives us a single file `CoinHunt`.

Let's take a look at the file with [Detect It Easy](https://github.com/horsicq/Detect-It-Easy), a useful program for determine the type of files and signatures of common compilers, packers, etc.

![PE file coinhunt shown in detect it easy](/coinhunt_1.png)

DIE recognizes this file as a [UPX](https://github.com/upx/upx)-packed PE ([portable executable](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)) file. All other signatures can be ignored since they are of the packer and not the original executable. I thought of 3 possible scenarios after seeing this (from increasing order of likely-hood):

1. The file is packed with a modified version of UPX.
2. The file is packed with a packer that pretends to be UPX, or DIE's signatures are wrong.
3. The file is packed with a unmodified version of UPX.

As a sanity check, I decided to verify that this wasn't a unmodified version of UPX, even though DIE says otherwise.

`$ upx -d CoinHunt`

```txt
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.2       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 3rd 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     15360 <-      9728   63.33%    win64/pe     CoinHunt

Unpacked 1 file.
```

???????

It turns out that it's just unmodified UPX and we didn't have to do any manual unpacking :D

Since this is a MSVC C/C++ binary, I opened it up in the industry standard disassembler, [IDA Pro](https://hex-rays.com/ida-pro/)

Load the binary as a x86-64 PE with the default options...

![Load a new file dialog in IDA PRO](/coinhunt_2.png)

IDA finds and drops me off at the [main function](https://learn.microsoft.com/en-us/cpp/c-language/main-function-and-program-execution?view=msvc-170)

![Disassembly of main function in IDA PRO](/coinhunt_3.png)

Let's hit F5 to decompile the binary...

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  HANDLE coin1_handle;
  HANDLE coin2_handle;
  HANDLE coin3_handle;
  HANDLE coin4_handle;
  const char *ascii_flag;
  char wrong_file_msg[56];
  DWORD NumberOfBytesWritten = 0;

  strcpy(wrong_file_msg, "Wrong Coin \n,---. \n' __O>` \n( (__/  ) \n.-----, \n `---'\n");
  
  CreateDirectoryW(L"C:\\Users\\Public\\Documents\\Coin1", NULL);
  coin1_handle = CreateFileW(L"C:\\Users\\Public\\Documents\\Coin1\\Coin1.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  WriteFile(coin1_handle, wrong_file_msg, strlen(wrong_file_msg), &NumberOfBytesWritten, NULL);
  CloseHandle(coin1_handle);

  CreateDirectoryW(L"C:\\Users\\Public\\Downloads\\Coin2", NULL);
  coin2_handle = CreateFileW(L"C:\\Users\\Public\\Downloads\\Coin2\\Coin2.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  WriteFile(coin2_handle, wrong_file_msg, strlen(wrong_file_msg), &NumberOfBytesWritten, NULL);
  CloseHandle(coin2_handle);
  
  CreateDirectoryW(L"C:\\Users\\Public\\Music\\Coin3", NULL);
  coin3_handle = CreateFileW(L"C:\\Users\\Public\\Music\\Coin3\\Coin3.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  WriteFile(coin3_handle, wrong_file_msg, strlen(wrong_file_msg), &NumberOfBytesWritten, NULL);
  CloseHandle(coin3_handle);
  
  ascii_flag = "      __-----__ \n"
                "..;;;--'~~~`--;;;.. \n"
                "/;-~EspionageCTF{$ilver@_C0In}~-. \n"
                "//      ,;;;;;;;;      \\ \n"
                ".//      ;;;;;           \\ \n"
                "||       ;;;;(   /.|       || \n"
                "||       ;;;;;;;   _      || \n"
                "||       ';;  ;;;;=        || \n"
                "||LIBERTY | '';;;;;;      || \n"
                "\\     ,| '  '|><| 1995 // \n"
                " \\   |     |        A // \n"
                "  `;.,|.    |      '.-'/ \n"
                "     ~~;;;,._|___.,-;;;~' \n"
                "         ''=--' \n";
    
  CreateDirectoryW(L"C:\\Users\\Public\\Pictures\\Coin4", NULL);
  coin4_handle = CreateFileW(L"C:\\Users\\Public\\Pictures\\Coin4\\Coin4.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  WriteFile(coin4_handle, ascii_flag, strlen(ascii_flag), &NumberOfBytesWritten, NULL);
  CloseHandle(coin4_handle);
  
  return 0;
}
```

We can get a very clear picture of what the binary does, writing to various directories in the `Public` user folder. The flag is visible in the ASCII art.
`EspionageCTF{$ilver@_C0In}`

## Skull (15 points)

We are given a encrypted 7-zip file, `Skull.7z`, and the password `infected`.

After extracting the zip file, we are once again greeted with a MSVC C/C++ binary. There are no DIE signatures for any packers, and we can confirm it's not packed by looking at the entropy graph. Both compression and encryption will reduce the uniqueness of the bytes in the PE file, making it less random. A consistently high entropy is a good sign a file is packed.

![Entropy graph of skull binary in detect it easy](/skull_1.png)

Loading the PE in IDA Pro, and examining the main function.. we find the flag, in plaintext? What?!

```c
qmemcpy(flag_buffer, "{F@LC0N$_B!rd}", sizeof(flag_buffer));
```

Looking at the disassembly, we see a stack string, that contains our flag.

At the time of writing, both IDA Pro (8.3) and [Binary Ninja](https://binary.ninja/) (3.5.4526) correctly recognize this pattern and outline the instructions into a `memcpy()`, with only [Ghidra](https://ghidra-sre.org/) (11.0) failing. To future challenge authors, it seems like just using simple stack strings won't be tricking even the most novice reverse engineers anymore!

```txt
mov     [rbp+320h+var_20], 4C40467Bh
mov     [rbp+320h+var_1C], 244E3043h
mov     [rbp+320h+var_18], 7221425Fh
mov     [rbp+320h+var_14], 7D64h
```

```txt
mov     [rbp+320h+var_20], 'L@F{'
mov     [rbp+320h+var_1C], '$N0C'
mov     [rbp+320h+var_18], 'r!B_'
mov     [rbp+320h+var_14], '}d'
```

`EspionageCTF{F@LC0N$_B!rd}`

## Top Secret (15 points)

This challenge provide us with another encrypted 7zip archive, with the same password of `infected`. The extracted binary is another MSVC C/C++ PE file, and I loaded it into IDA Pro just as with the last challenge.

The flag in this challenge is in plain text in the `.rodata` section, and you can even `strings` for it. In the disassembly, the `strcpy()` call is outlined, revealing the flag.

```c
strcpy(lpBuffer, "EspionageCTF{CL@55iFed_C0nt$nt}");
```

`EspionageCTF{CL@55iFed_C0nt$nt}`

## ScrambledSquares (87 points)

Now this sponsor challenge from Aliakbar Zahravi at [TrendMicro](https://www.trendmicro.com) is a lot more interesting, uses techniques similar to real malware like dynamic api resolving, and was overall very fun to solve. Thanks for creating it!

We are given an archive containing a lot of `.DAT` files, what looks to be presumably a decrypter written in Python, `ctf.py`, and the following instructions:

```txt
CTF Challenge: Brief Hints

    •    Stage 1: Investigate the Python code’s method of serial number generation. Focus on MD5 and the relevance of dates.
    •    Stage 2: Look for hidden elements within the code for the password.
    •    Stage 3: Use the password wisely to reveal a new file format.
    •    Stage 4: The executable holds clues about its own usage.
    •    Stage 5: Apply what you learned from the exe analysis for decryption.
    •    Stage 6: A QR code awaits, holding more than meets the eye.
    •    Stage 7: Decode the QR contents to transition to a new file type.
    •    Stage 8: Unpack the final layer to uncover the flag.

Remember: Each clue is a piece of a larger puzzle. Pay attention to the details and think creatively.
```

```python
import sys 
from PyQt5 .QtWidgets import QApplication ,QWidget ,QLineEdit ,QPushButton ,QVBoxLayout ,QLabel 
import hashlib 
import subprocess 
from Crypto .Cipher import AES 
from Crypto .Protocol .KDF import PBKDF2 
import os 
from datetime import datetime 
import pefile 
def tthfghfjfr4343 (OOOO00000OOO00O00 ):
    OOOO00O00000OOOOO =hashlib .md5 ()
    with open (OOOO00000OOO00O00 ,"rb")as OO0O0O00OOOOO0OOO :
        for OOOOOO0OO0O0OOO00 in iter (lambda :OO0O0O00OOOOO0OOO .read (4096 ),b""):
            OOOO00O00000OOOOO .update (OOOOOO0OO0O0OOO00 )
    return OOOO00O00000OOOOO .hexdigest ()
class CTFChallenge (QWidget ):
    def __init__ (O0OOOOOOO00OO0OO0 ):
        O0OOOOOOO00OO0OO0 .attemptCount =0 
        O0OOOOOOO00OO0OO0 .final_password =(((0x2a |0x42 )>=(0x8d |0x5 ))and (chr (0x2d ^0x62 ))or (chr (0x53 &0x57 )))+(((0x84 |0x1 )<(0xc0 |0xc0 ))and (chr (0x34 |0x60 ))or (chr (0x7c &0x7b )))+(((0x2a |0x7a )>(0x17c &0x114 ))and (chr (0x7a |0x20 ))or (chr (0x72 |0x22 )))+(((0x105 |0x121 )<=(0x2 |0x110 ))and (chr (0x2a ^0x1 ))or (chr (0x23 |0x11 )))+(((0xc0 |0xe2 )>(0x122 ^0x3d ))and (chr (0x3f &0x32 ))or (chr (0x10 |0x24 )))+(((0x83 |0x8 )<=(0xb4 |0xec ))and (chr (0x48 |0x2d ))or (chr (0x28 |0x60 )))+(((0x84 |0x1 )>(0x94 |0x84 ))and (chr (0x40 |0x3 ))or (chr (0x4b &0x43 )))+(((0x60 |0x10 )<=(0x17e &0x118 ))and (chr (0x11 |0x21 ))or (chr (0x31 &0x35 )))+(((0x48 |0x32 )==(0x31 |0x63 ))and (chr (0x26 |0x45 ))or (chr (0x77 &0x78 )))+(((0xd7 &0xfb )<=(0x3c ^0xdf ))and (chr (0x68 |0x48 ))or (chr (0x30 ^0x55 )))+(((0xf3 &0xbc )!=(0x14e &0x10f ))and (chr (0x33 |0x23 ))or (chr (0x31 ^0x2 )))+(((0x83 |0xb0 )>=(0x1d0 ^0xcb ))and (chr (0x3a ^0x56 ))or (chr (0x3b ^0x49 )))+(((0xa0 |0xa0 )!=(0x94 |0x90 ))and (chr (0x4e |0x5f ))or (chr (0x40 |0x5d )))+(((0x151 &0x190 )>=(0xd7 &0xdf ))and (chr (0x34 &0x3b ))or (chr (0x13 ^0x34 )))+(((0xff &0xff )==(0xbd &0xb5 ))and (chr (0x11 ^0x65 ))or (chr (0x76 |0x46 )))+(((0xee &0xdf )==(0x56 |0x8d ))and (chr (0x7 ^0x3c ))or (chr (0x33 |0x22 )))+(((0x15d ^0x76 )>(0xff &0xfe ))and (chr (0x30 |0x42 ))or (chr (0x78 &0x7d )))+(((0x2 ^0x90 )==(0x88 ^0x35 ))and (chr (0x15 ^0x7c ))or (chr (0x7c &0x6d )))+(((0x12 |0x112 )>=(0x92 |0xb ))and (chr (0x20 |0x10 ))or (chr (0x21 |0x30 )))+(((0xa1 |0xcc )<=(0x147 &0x107 ))and (chr (0x30 |0x4 ))or (chr (0x28 |0x11 )))+(((0x6e &0x7f )<=(0xc |0x7b ))and (chr (0x65 &0x74 ))or (chr (0x64 |0x44 )))
        super ().__init__ ()
        O0OOOOOOO00OO0OO0 .fgdgdfh4545 ()
    def fgdgdfh4545 (OO00O0O00O000O0O0 ):
        OO00O0O00O000O0O0 .setWindowTitle ('ISSessions 2024 CTF')
        OO00O0O00O000O0O0 .resize (400 ,100 )
        OO00O0O00O000O0O0 .serialNumberInput =QLineEdit (OO00O0O00O000O0O0 )
        OO00O0O00O000O0O0 .validateButton =QPushButton ('Validate',OO00O0O00O000O0O0 )
        OO00O0O00O000O0O0 .validateButton .clicked .connect (OO00O0O00O000O0O0 .kljfskjyi737iy2 )
        OO00O0O00O000O0O0 .resultLabel =QLabel ('',OO00O0O00O000O0O0 )
        OO00O0O00O000O0O0 .passwordInput =QLineEdit (OO00O0O00O000O0O0 )
        OO00O0O00O000O0O0 .passwordInput .setEchoMode (QLineEdit .Password )
        OO00O0O00O000O0O0 .passwordInput .hide ()
        OO00O0O00O000O0O0 .serialLabel =QLabel ((((0xcc^0x35)==(0x54|0x68))and(chr(0x47^0xb))or(chr(0x55&0x4d)))+(((0xbf&0x9a)<=(0x41|0x64))and(chr(0x1c^0x69))or(chr(0x7f&0x6e)))+(((0x30^0x5a)<=(0x80|0x0))and(chr(0x4|0x70))or(chr(0x79&0x7a)))+(((0xaa^0x67)!=(0x16a^0x75))and(chr(0x65&0x75))or(chr(0x3f^0x5f)))+(((0x15d&0x19f)!=(0x49^0xb9))and(chr(0x76&0x72))or(chr(0x33|0x47)))+(((0x67^0xda)>(0xf5&0xf6))and(chr(0x32^0x14))or(chr(0x39&0x20)))+(((0x199^0x98)!=(0x95|0xd3))and(chr(0x5f&0x73))or(chr(0x7d&0x5d)))+(((0xc8^0x3d)==(0x108|0x110))and(chr(0x6e&0x7d))or(chr(0x67&0x75)))+(((0x110&0x1f0)<(0xc1^0x5))and(chr(0x68|0xe))or(chr(0x34^0x46)))+(((0x22|0x122)==(0xfc&0xfd))and(chr(0x7f^0x1c))or(chr(0x4^0x6d)))+(((0xc1|0xea)>=(0xbb&0xeb))and(chr(0x40|0x21))or(chr(0x5f&0x57)))+(((0xf6&0xfe)==(0x1a0^0xb2))and(chr(0x15^0x64))or(chr(0x28|0x64)))+(((0xf2|0x90)<(0x56^0xb9))and(chr(0x17&0x17))or(chr(0x20|0x20)))+(((0x94^0x4)!=(0xfd&0xee))and(chr(0x5e&0x4f))or(chr(0x52&0x72)))+(((0x87&0x9f)<(0xca&0x8b))and(chr(0x77&0x7d))or(chr(0x66^0x17)))+(((0xeb&0x9f)>=(0x115|0x10a))and(chr(0x10|0x72))or(chr(0x59^0x34)))+(((0x65|0x4c)==(0xa3^0x4e))and(chr(0x28|0x4a))or(chr(0x2f^0x4d)))+(((0xb5^0x3)>(0xbe&0xb3))and(chr(0x5d^0x38))or(chr(0x3e^0x58)))+(((0x121|0x10a)>=(0x4b^0xe1))and(chr(0x50^0x22))or(chr(0x2^0x74)))+(((0x4e^0xc7)>=(0x70&0x72))and(chr(0x3a&0x3f))or(chr(0x4e^0xf))),OO00O0O00O000O0O0 )
        OO00O0O00O000O0O0 .passwordLabel =QLabel ((((0xe3^0x1e5)<=(0xeb&0xf2))and(chr(0x10^0x2b))or(chr(0x61^0x24)))+(((0x10^0xa7)!=(0x107&0x13f))and(chr(0xa|0x64))or(chr(0x7f&0x77)))+(((0x1c7^0xcc)!=(0x81|0x81))and(chr(0x64|0x70))or(chr(0x28|0x4b)))+(((0xa3&0xf7)>(0x138&0x155))and(chr(0x69^0x36))or(chr(0x11^0x74)))+(((0x88|0xa8)==(0x13^0xfd))and(chr(0x74|0x63))or(chr(0x72&0x7f)))+(((0x8d|0xed)==(0xe2|0x8a))and(chr(0xb^0x12))or(chr(0xe^0x2e)))+(((0x1b^0xeb)<=(0x90|0x47))and(chr(0x7a&0x50))or(chr(0x0|0x50)))+(((0x3d^0x13c)!=(0x3d^0x4c))and(chr(0x71&0x6f))or(chr(0x43^0x24)))+(((0x82^0x18f)>(0x13f&0x12a))and(chr(0x58^0x2d))or(chr(0x73|0x60)))+(((0x2a|0xb9)!=(0xc1&0xdf))and(chr(0x70|0x23))or(chr(0x44^0x31)))+(((0x31^0x98)>(0x11f&0x18d))and(chr(0x77&0x73))or(chr(0x77&0x77)))+(((0xc^0x7f)!=(0x6f&0x6e))and(chr(0x7f&0x6f))or(chr(0x76&0x74)))+(((0xb3&0xb2)>(0x10|0x80))and(chr(0x7b&0x72))or(chr(0x40|0x68)))+(((0xbf^0x5b)==(0xd0|0xc1))and(chr(0x62^0xc))or(chr(0x36^0x52)))+(((0x8^0xa3)<(0x12a&0x19e))and(chr(0x3b&0x3a))or(chr(0x24|0x30))),OO00O0O00O000O0O0 )
        OO00O0O00O000O0O0 .passwordLabel .hide ()
        OOO00O0OO0O0000OO =QVBoxLayout (OO00O0O00O000O0O0 )
        OOO00O0OO0O0000OO .addWidget (OO00O0O00O000O0O0 .serialLabel )
        OOO00O0OO0O0000OO .addWidget (OO00O0O00O000O0O0 .serialNumberInput )
        OOO00O0OO0O0000OO .addWidget (OO00O0O00O000O0O0 .resultLabel )
        OOO00O0OO0O0000OO .addWidget (OO00O0O00O000O0O0 .passwordLabel )
        OOO00O0OO0O0000OO .addWidget (OO00O0O00O000O0O0 .passwordInput )
        OOO00O0OO0O0000OO .addWidget (OO00O0O00O000O0O0 .validateButton )
    def dfjshdfk7372gjb (OO0OO0OO000O0O0OO ,O00OO0OO00O00OO00 ):
        try :
            O0O0OO00O0O00O0OO =pefile .PE (O00OO0OO00O00OO00 )
            return True 
        except :
            return False 
    def kljfskjyi737iy2 (O00OOOO00OO000000 ):
        OO0OO0OOO0O0O0000 =O00OOOO00OO000000 .serialNumberInput .text ()
        OO0OOOOOOOOO0OOOO =str (datetime .now ().year )
        O0OO0O000O000O000 =tthfghfjfr4343 ((((0x2a ^0x54 )<=(0x48 ^0x3e ))and (chr (0xf ^0x43 ))or (chr (0x8 ^0x4a )))+(((0x8 |0x89 )==(0xdf &0xeb ))and (chr (0x2f &0x3f ))or (chr (0x9 ^0x3b )))+(((0x98 ^0x26 )<=(0xa0 ^0x7a ))and (chr (0x6b &0x53 ))or (chr (0x4d &0x66 )))+(((0xb9 ^0x4d )>(0x99 ^0x1bb ))and (chr (0x1 |0x34 ))or (chr (0x37 &0x33 )))+(((0xa5 &0xb4 )<=(0x44 |0xc4 ))and (chr (0x56 &0x64 ))or (chr (0x3e ^0x5 )))+(((0x2e |0xa7 )<(0x5f ^0x93 ))and (chr (0x30 |0x14 ))or (chr (0x25 |0x19 )))+(((0xc4 ^0x58 )<=(0x68 |0x50 ))and (chr (0x38 ^0x75 ))or (chr (0x75 &0x45 )))+(((0x44 ^0x98 )<(0x4b ^0xe7 ))and (chr (0x39 |0x39 ))or (chr (0x4 ^0x31 )))+(((0x45 |0x28 )<=(0x4e ^0x89 ))and (chr (0x2e &0x2f ))or (chr (0x2c &0x3e )))+(((0xf5 &0xff )==(0x6b &0x6f ))and (chr (0x2a ^0x6c ))or (chr (0x76 ^0x32 )))+(((0xd5 ^0x5 )!=(0xc ^0xbe ))and (chr (0x7c ^0x3d ))or (chr (0xb ^0x33 )))+(((0x67 &0x77 )>=(0xc7 ^0x22 ))and (chr (0x50 |0x51 ))or (chr (0x74 &0x5d ))))
        if OO0OO0OOO0O0O0000 .startswith (OO0OOOOOOOOO0OOOO )and OO0OO0OOO0O0O0000 [len (OO0OOOOOOOOO0OOOO )+1 :len (OO0OOOOOOOOO0OOOO )+33 ]==O0OO0O000O000O000 :
            O00OOOO00OO000000 .resultLabel .setText ((((0xc2&0xe9)<=(0x10a&0x1ea))and(chr(0x53&0x5b))or(chr(0x72^0x3c)))+(((0x1b^0x132)<(0x1a^0x13d))and(chr(0x72^0x29))or(chr(0x5b^0x3e)))+(((0x97^0x58)>(0x76&0x7f))and(chr(0x7f^0xd))or(chr(0x7a&0x76)))+(((0x53|0x70)>=(0x50^0x14b))and(chr(0x7f&0x65))or(chr(0x7a^0x13)))+(((0x109|0x129)>=(0x101|0x1a))and(chr(0x49^0x28))or(chr(0x66^0x7)))+(((0xb7&0xfd)<=(0x8f|0xaa))and(chr(0x4d|0x20))or(chr(0xf^0x63)))+(((0x184&0x11b)>(0x110|0x2))and(chr(0x2|0x22))or(chr(0x20|0x0)))+(((0x82|0x98)>=(0xef|0xc6))and(chr(0x76&0x75))or(chr(0xc|0x6e)))+(((0x6d&0x75)>=(0x9c^0x4))and(chr(0x26|0x56))or(chr(0x1c^0x69)))+(((0xa0|0xa4)>=(0x86^0x31))and(chr(0x45^0x28))or(chr(0x4^0x69)))+(((0x16c^0x62)<(0x40|0x80))and(chr(0x65|0x25))or(chr(0x72&0x6a)))+(((0x76^0x5)>(0xf0&0xa1))and(chr(0x7b&0x61))or(chr(0x75&0x65)))+(((0x50|0xd2)==(0x48|0x84))and(chr(0x25|0x75))or(chr(0x30|0x52)))+(((0x64|0xbc)>(0xd1|0x86))and(chr(0x38&0x24))or(chr(0x3d^0x1e)))+(((0x8c^0x62)<=(0xd7&0xd7))and(chr(0x70&0x76))or(chr(0x7b&0x69)))+(((0x80|0xa2)!=(0xa1|0x80))and(chr(0x20|0x53))or(chr(0x2d|0x6b)))+(((0x55^0xe9)>=(0xb1&0xb5))and(chr(0x28&0x24))or(chr(0x2f&0x25)))+(((0xb7&0xb3)!=(0xf5&0xfd))and(chr(0x6a^0x1c))or(chr(0xbe^0x3e)))+(((0xa3^0x57)>(0x11f&0x1ec))and(chr(0x1a^0x42))or(chr(0x28^0x49)))+(((0x0^0xf8)==(0xd^0xb7))and(chr(0x79^0x13))or(chr(0x7c&0x6c)))+(((0x18e&0x147)<(0x5f^0xa3))and(chr(0x7a^0xb))or(chr(0x6b&0x79)))+(((0x92|0x3e)<=(0x13b&0x1a9))and(chr(0x4|0x60))or(chr(0x7b&0x6e)))+(((0x5^0x6b)>=(0x9c|0x28))and(chr(0x29&0x29))or(chr(0x3e^0x1f))))
            O00OOOO00OO000000 .passwordLabel .show ()
            O00OOOO00OO000000 .passwordInput .show ()
            O00OOOO00OO000000 .validateButton .clicked .disconnect ()
            O00OOOO00OO000000 .validateButton .clicked .connect (O00OOOO00OO000000 .hkfhd98273i4ha )
        else :
            O00OOOO00OO000000 .attemptCount +=1 
            O00OOOO00OO000000 .resultLabel .setText (f'Invalid number. Attempts left: {3 - O00OOOO00OO000000.attemptCount}')
            if O00OOOO00OO000000 .attemptCount >=3 :
                O00OOOO00OO000000 .gdfhfgj45645y4 ()
    def hkfhd98273i4ha (OO00OOOO000O0000O ):
        if OO00OOOO000O0000O .passwordInput .text ()==OO00OOOO000O0000O .final_password :
            OO00OOOO000O0000O .resultLabel .setText ((((0x6d |0xd5 )>=(0x90 |0x98 ))and (chr (0x50 |0x10 ))or (chr (0x59 &0x4f )))+(((0xff &0xbd )>(0x8 ^0xd0 ))and (chr (0x63 &0x6b ))or (chr (0x6b &0x61 )))+(((0x2c ^0xc9 )>=(0x80 |0x80 ))and (chr (0x7b &0x77 ))or (chr (0x1c ^0x65 )))+(((0x9a ^0x1bc )!=(0x43 ^0x34 ))and (chr (0x50 |0x63 ))or (chr (0x77 &0x7d )))+(((0xac |0xaa )<(0x15f &0x1b5 ))and (chr (0x76 |0x11 ))or (chr (0x7f &0x77 )))+(((0xfc ^0xa )!=(0xd4 &0x94 ))and (chr (0x7f &0x6f ))or (chr (0x64 |0x52 )))+(((0x58 ^0x22 )!=(0xd6 ^0x6e ))and (chr (0x3d ^0x4f ))or (chr (0x74 &0x71 )))+(((0xfb &0xf6 )>=(0x95 ^0x26 ))and (chr (0x64 &0x76 ))or (chr (0x76 ^0x2d )))+(((0xf7 &0x97 )<(0x75 ^0xe1 ))and (chr (0x1 |0x1b ))or (chr (0x20 &0x34 )))+(((0x85 |0x70 )!=(0xdf &0xdc ))and (chr (0x41 |0x29 ))or (chr (0x77 &0x73 )))+(((0x64 &0x66 )>(0x49 ^0x35 ))and (chr (0x76 &0x7e ))or (chr (0x63 ^0x10 )))+(((0xc1 &0x85 )<=(0x11f |0x1f ))and (chr (0x25 ^0x5 ))or (chr (0x17 ^0x32 )))+(((0x10e &0x12a )<(0xfa &0xf6 ))and (chr (0x3f ^0x46 ))or (chr (0x77 &0x7e )))+(((0xf1 |0xc1 )!=(0x6c ^0x175 ))and (chr (0x41 |0x60 ))or (chr (0x4d ^0x2f )))+(((0xa1 |0x64 )<=(0xbf &0xae ))and (chr (0x67 |0x60 ))or (chr (0x7c &0x6c )))+(((0xbc ^0x44 )<=(0x71 ^0xc ))and (chr (0x71 &0x7c ))or (chr (0x8 |0x61 )))+(((0x7e &0x7f )!=(0xa1 |0x8c ))and (chr (0x64 &0x65 ))or (chr (0x20 |0x6a )))+(((0x109 |0x8 )!=(0xd3 &0xd5 ))and (chr (0x23 &0x31 ))or (chr (0x3f ^0x1c ))))
            OO00OOOO000O0000O .jdfjghkhkd32 ()
        else :
           OO00OOOO000O0000O .attemptCount +=1 
           OO00OOOO000O0000O .resultLabel .setText (f'Invalid. Attempts left: {3 - OO00OOOO000O0000O.attemptCount}')
           if OO00OOOO000O0000O .attemptCount >=3 :
               OO00OOOO000O0000O .gdfhfgj45645y4 ()
    def gdfhfgj45645y4 (OO00OO000O00O00OO ):
        OO00OO000O00O00OO .resultLabel .setText ('Too many incorrect attempts. Application will exit.')
        QApplication .quit ()
    def jdfjghkhkd32 (O0O000OO0O0O00O00 ):
        O0OOOO0OOOO00O0OO =(((0xa0 ^0x45 )>=(0x84 ^0x19a ))and (chr (0x28 |0x19 ))or (chr (0x66 &0x43 )))+(((0x15 ^0x62 )==(0x54 ^0xab ))and (chr (0x37 &0x39 ))or (chr (0x2d ^0x1f )))+(((0xdf &0xfd )==(0x85 |0x11 ))and (chr (0x41 |0x1 ))or (chr (0x3 |0x40 )))+(((0xf7 &0xb4 )>(0x80 |0x48 ))and (chr (0x28 |0x30 ))or (chr (0x32 |0x31 )))+(((0x3e ^0x83 )<(0x7e &0x74 ))and (chr (0x3d &0x3f ))or (chr (0x0 |0x44 )))+(((0x63 ^0x87 )==(0xab &0xe3 ))and (chr (0x2d |0x1 ))or (chr (0x36 ^0x2 )))+(((0xb4 |0xa0 )<=(0xc0 |0xc1 ))and (chr (0x45 &0x4f ))or (chr (0xc |0x45 )))+(((0x3a ^0xf4 )==(0x6 ^0x63 ))and (chr (0x15 ^0x2a ))or (chr (0x35 &0x35 )))+(((0xdd &0xb7 )==(0xd7 &0xbf ))and (chr (0x27 |0x4 ))or (chr (0x24 |0xa )))+(((0xf9 &0xf1 )>=(0x4 |0x84 ))and (chr (0x45 &0x4e ))or (chr (0x17 ^0x5c )))+(((0xa6 |0x6 )==(0x101 &0x1f7 ))and (chr (0x5 |0x45 ))or (chr (0x20 ^0x61 )))+(((0xa7 ^0xc )<=(0x95 ^0x14 ))and (chr (0x4d ^0x1c ))or (chr (0x44 |0x50 )))
        OO0OO00O0000OOOO0 =O0O000OO0O0O00O00 .final_password 
        OO00OOO0OO00O0OO0 =(((0xbb &0xb7 )!=(0x80 |0x8 ))and (chr (0x51 |0x11 ))or (chr (0x7b &0x5f )))+(((0x75 ^0xb7 )>(0xff &0xf5 ))and (chr (0x0 ^0x3a ))or (chr (0x56 &0x45 )))+(((0x48 ^0x3a )<(0x8a &0xab ))and (chr (0x25 |0x60 ))or (chr (0x14 ^0x7b )))+(((0x65 ^0x1e )!=(0xf4 &0xb6 ))and (chr (0x3 |0x62 ))or (chr (0x4e ^0x23 )))+(((0xf5 |0xb0 )<(0x27 |0x48 ))and (chr (0x73 |0x73 ))or (chr (0x50 |0x32 )))+(((0xd9 &0xef )>(0x5 |0xe2 ))and (chr (0x79 &0x79 ))or (chr (0x7f &0x79 )))+(((0x1ae ^0xaa )<(0xc9 |0xc3 ))and (chr (0x4a |0x63 ))or (chr (0x71 &0x70 )))+(((0x23 ^0x4a )>=(0xfe &0xdc ))and (chr (0x1 ^0x73 ))or (chr (0x13 ^0x67 )))+(((0x6d ^0x14c )<=(0xcb &0xeb ))and (chr (0x7 ^0x77 ))or (chr (0x2d |0x67 )))+(((0xc7 ^0x68 )<=(0x4 |0xa0 ))and (chr (0x30 ^0x5a ))or (chr (0x27 ^0x55 )))+(((0x10c |0x0 )<(0x107 ^0xe ))and (chr (0x3f ^0x8 ))or (chr (0x19 ^0x37 )))+(((0x81 ^0x71 )!=(0x4e ^0xa8 ))and (chr (0x21 |0x44 ))or (chr (0x19 ^0x44 )))+(((0x10a |0x5 )==(0x7f &0x7f ))and (chr (0x5f ^0x21 ))or (chr (0x7a &0x79 )))+(((0xd7 ^0x1fe )>=(0xd |0x91 ))and (chr (0x67 ^0x2 ))or (chr (0x77 ^0x1d )))
        with open (O0OOOO0OOOO00O0OO ,'rb')as OO0000O0O000O0O00 :
            OOOOO000OOOO0000O =OO0000O0O000O0O00 .read (16 )
            OO000OOO0OOO00000 =OO0000O0O000O0O00 .read (16 )
            O0OOO00OO00OOO000 =OO0000O0O000O0O00 .read ()
        OOOO000OOOO00OO00 =PBKDF2 (OO0OO00O0000OOOO0 ,OOOOO000OOOO0000O ,dkLen =32 )
        O0OOOO0O0OO0000OO =AES .new (OOOO000OOOO00OO00 ,AES .MODE_CBC ,iv =OO000OOO0OOO00000 )
        O0OOO0O0O0O0O0O0O =O0OOOO0O0OO0000OO .decrypt (O0OOO00OO00OOO000 )
        O00000OO00000000O =O0OOO0O0O0O0O0O0O [-1 ]
        O0OOO0O0O0O0O0O0O =O0OOO0O0O0O0O0O0O [:-O00000OO00000000O ]
        with open (OO00OOO0OO00O0OO0 ,'wb')as OO0000O0O000O0O00 :
            OO0000O0O000O0O00 .write (O0OOO0O0O0O0O0O0O )
        if O0O000OO0O0O00O00 .dfjshdfk7372gjb (OO00OOO0OO00O0OO0 ):
            O0O000OO0O0O00O00 .resultLabel .setText ((((0x44^0xf4)==(0x1a^0xff))and(chr(0x3f&0x3d))or(chr(0x0|0x44)))+(((0x104|0x105)>(0x40|0x88))and(chr(0x75&0x67))or(chr(0x19^0x70)))+(((0x90|0x80)>(0x3f^0x4b))and(chr(0x7b&0x63))or(chr(0x6d&0x79)))+(((0x145^0x60)==(0xa|0x108))and(chr(0x28|0x52))or(chr(0x7b&0x72)))+(((0x10c|0xd)>(0x103|0x3))and(chr(0x79&0x7d))or(chr(0x7e&0x7d)))+(((0x30|0x98)<(0x9d&0xb1))and(chr(0x3|0x71))or(chr(0x72&0x79)))+(((0xfe&0xec)==(0xd^0xae))and(chr(0x7d&0x7d))or(chr(0x59^0x2d)))+(((0x77^0xe2)>(0x67&0x6d))and(chr(0x23^0x4a))or(chr(0x26|0x64)))+(((0xa5^0x1ad)<(0x76&0x77))and(chr(0x46^0x36))or(chr(0x57^0x38)))+(((0xd6&0xd9)==(0x11e&0x17f))and(chr(0x6f&0x6d))or(chr(0x6f&0x7e)))+(((0x8e|0x90)>=(0xff&0xff))and(chr(0x24^0x6))or(chr(0x13^0x33)))+(((0xbb&0xd9)<(0x15a&0x19a))and(chr(0x77&0x63))or(chr(0x64^0xf)))+(((0xd5&0xe1)==(0xbc&0xfe))and(chr(0x28|0x4e))or(chr(0x4b^0x24)))+(((0x7f^0x12)>(0x147&0x134))and(chr(0x63|0x5))or(chr(0x51^0x3c)))+(((0x40|0x80)!=(0xc8^0x2f))and(chr(0x73&0x78))or(chr(0x79&0x6a)))+(((0x1db^0xd1)<(0xd7&0xf7))and(chr(0x63|0x62))or(chr(0x1a^0x76)))+(((0x10a&0x1d8)<(0xf7&0x95))and(chr(0x5f|0x59))or(chr(0x54^0x31)))+(((0x141^0x4a)<=(0x39^0xd1))and(chr(0x6b|0x50))or(chr(0x37^0x43)))+(((0xf4&0xcc)>=(0x124|0x20))and(chr(0x7d^0x16))or(chr(0x25|0x41)))+(((0xdd&0xfe)<=(0xda|0x1c))and(chr(0x68^0xc))or(chr(0x7f&0x6b)))+(((0x9f&0x96)!=(0x1e|0x104))and(chr(0x2e&0x3e))or(chr(0x36&0x27)))+(((0x1f2^0xee)>(0x17f&0x111))and(chr(0x3^0x9))or(chr(0x1|0x11)))+(((0xa9|0xc1)==(0xec&0xa5))and(chr(0x6c^0x2e))or(chr(0x48|0x4c)))+(((0xcd&0xf7)>(0xbe&0xbd))and(chr(0x7f&0x6f))or(chr(0x6c|0x40)))+(((0x4a|0x63)>(0x1fa&0x122))and(chr(0x66&0x7f))or(chr(0x5b^0x3a)))+(((0x64|0x9c)==(0x45^0xad))and(chr(0x75&0x65))or(chr(0x7a^0x1e)))+(((0x7c&0x7e)<(0x9c&0x9b))and(chr(0x65|0x60))or(chr(0x60|0x61)))+(((0x132&0x1c2)<=(0xce&0xee))and(chr(0x76&0x77))or(chr(0x72&0x7a)))+(((0xd3|0x11)<=(0x4c^0xc3))and(chr(0x10|0x8))or(chr(0x0|0x20)))+(((0xac^0x70)<(0xec|0xc5))and(chr(0x28|0x48))or(chr(0x41|0x25)))+(((0xc9|0x49)>=(0xfd&0xff))and(chr(0x5a&0x5d))or(chr(0x66^0x7)))+(((0xa1|0x10)>=(0x88^0x5))and(chr(0x73&0x7f))or(chr(0x76^0x4)))+(((0x94|0x2c)<(0x6b^0x8f))and(chr(0x20|0x20))or(chr(0x1e&0x1b)))+(((0x0|0xc1)<=(0xaf&0xdf))and(chr(0x6b&0x7f))or(chr(0x22|0x42)))+(((0xa2^0x47)<(0x113|0x10b))and(chr(0x68^0xd))or(chr(0x6c^0x4)))+(((0xc3^0x64)==(0xdf&0xe5))and(chr(0xc|0x68))or(chr(0x6d&0x75)))+(((0xc4^0x25)>=(0xba^0x19c))and(chr(0x6d&0x79))or(chr(0x4e|0x22)))+(((0x17f&0x1a8)>=(0x4f^0xd9))and(chr(0x0^0x20))or(chr(0x8|0x20)))+(((0x102|0x2)!=(0x99|0xcd))and(chr(0x49^0x3a))or(chr(0x0|0x74)))+(((0x68^0xad)>(0x120^0x4))and(chr(0x8|0x5b))or(chr(0x61|0x20)))+(((0xa3^0x182)<(0xe7&0xe1))and(chr(0x62|0x50))or(chr(0x72^0x4)))+(((0x15e&0x10e)<=(0xd0|0xb0))and(chr(0x6f&0x7a))or(chr(0x65&0x7d)))+(((0xd^0x99)<=(0x1cf&0x107))and(chr(0x57^0x33))or(chr(0x6f&0x63)))+(((0xea^0x4b)!=(0x1d^0x112))and(chr(0x2e&0x3f))or(chr(0x4|0x2d))))
        else :
            O0O000OO0O0O00O00 .resultLabel .setText ('Invalid executable file.')
        O0O000OO0O0O00O00 .resultLabel .setText ((((0xd9^0x2)>(0xdf&0xef))and(chr(0x57&0x44))or(chr(0x35^0xb)))+(((0x23|0xc3)<(0x82|0x84))and(chr(0x69|0x6a))or(chr(0x65&0x7f)))+(((0x15^0x64)==(0xd5&0xff))and(chr(0x5c^0x39))or(chr(0x34^0x57)))+(((0xfd&0xa5)==(0x1a^0xfa))and(chr(0x7a&0x70))or(chr(0x12|0x60)))+(((0x82|0x40)>(0x44|0x88))and(chr(0x64|0x74))or(chr(0x41|0x38)))+(((0x2e|0xa2)==(0x41^0x80))and(chr(0x68^0xf))or(chr(0x76&0x78)))+(((0x15b^0x7c)<=(0x2|0x113))and(chr(0x5e^0x26))or(chr(0x7c&0x76)))+(((0x8b^0x19e)!=(0x6^0x73))and(chr(0x69&0x6b))or(chr(0x6^0x75)))+(((0x13f&0x1ab)<(0xfd&0xff))and(chr(0x7d&0x74))or(chr(0x4f|0x68)))+(((0x87^0x4e)<(0x6b&0x6b))and(chr(0x11|0x71))or(chr(0x4e^0x20)))+(((0x8|0xe8)>(0xf^0x67))and(chr(0x20|0x20))or(chr(0x14|0x18)))+(((0xe3|0x76)<=(0xc1|0x1b))and(chr(0x4d^0x21))or(chr(0x63&0x67)))+(((0x10c|0x8)>=(0xd3&0xf3))and(chr(0x20^0x4f))or(chr(0x67&0x77)))+(((0x8|0xa4)>=(0x56^0xf3))and(chr(0x65^0x8))or(chr(0x14^0x7f)))+(((0xe7&0xab)<=(0xb2|0x17))and(chr(0x38^0x48))or(chr(0x69|0x59)))+(((0x11b&0x19f)!=(0xfb&0xd9))and(chr(0x7d&0x6c))or(chr(0x6b&0x69)))+(((0x2|0x92)<(0xc7&0xa3))and(chr(0x6e&0x6e))or(chr(0x1b^0x7e)))+(((0x92|0x4)!=(0x166&0x13b))and(chr(0x1e^0x6a))or(chr(0x28^0x58)))+(((0xc7&0xad)>(0x81|0x51))and(chr(0x6e&0x74))or(chr(0x65|0x60)))+(((0x48|0x24)<(0xb6&0x96))and(chr(0x40|0x64))or(chr(0x7b&0x67)))+(((0xc2^0x4)<=(0x96&0x95))and(chr(0x3e&0x33))or(chr(0x22|0xc))))
if __name__ =='__main__':
    app =QApplication (sys .argv )
    ex =CTFChallenge ()
    ex .show ()
    sys .exit (app .exec_ ())

```

Ouch.. let's make that more readable. We can evaluate all the obfuscated strings with the python interpreter, and then just replace them. We can normalize a lot of the variable names by looking at the documentation for a lot of the python libraries, and by renaming the first argument for all the class methods to the conventional name`self`.

```python
import sys
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QLabel,
)
import hashlib
import subprocess
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import os
from datetime import datetime
import pefile


def md5sum(datfile):
    hasher = hashlib.md5()
    with open(datfile, "rb") as f:
        for i in iter(lambda: f.read(4096), b""):
            hasher.update(i)
    return hasher.hexdigest()


class CTFChallenge(QWidget):
    def __init__(self):
        self.attemptCount = 0
        self.final_password = "Str34mC1ph3r_0v3rl04d"
        super().__init__()
        self.init_window()

    def init_window(self):
        self.setWindowTitle("ISSessions 2024 CTF")
        self.resize(400, 100)
        self.serialNumberInput = QLineEdit(self)
        self.validateButton = QPushButton("Validate", self)
        self.validateButton.clicked.connect(self.check_serial)
        self.resultLabel = QLabel("", self)
        self.passwordInput = QLineEdit(self)
        self.passwordInput.setEchoMode(QLineEdit.Password)
        self.passwordInput.hide()
        self.serialLabel = QLabel("Enter Serial Number:", self)
        self.passwordLabel = QLabel("Enter Password:", self)
        self.passwordLabel.hide()
        box = QVBoxLayout(self)
        box.addWidget(self.serialLabel)
        box.addWidget(self.serialNumberInput)
        box.addWidget(self.resultLabel)
        box.addWidget(self.passwordLabel)
        box.addWidget(self.passwordInput)
        box.addWidget(self.validateButton)

    def is_valid_PE(self, pefilename):
        try:
            result = pefile.PE(pefilename)
            return True
        except:
            return False

    def check_serial(self):
        serial_input = self.serialNumberInput.text()
        year = str(datetime.now().year)
        md5_hash = md5sum("B2C3D4E5.DAT")
        if (
            serial_input.startswith(year)
            and serial_input[len(year) + 1 : len(year) + 33] == md5_hash
        ):
            self.resultLabel.setText("Serial number is valid!")
            self.passwordLabel.show()
            self.passwordInput.show()
            self.validateButton.clicked.disconnect()
            self.validateButton.clicked.connect(self.check_password)
        else:
            self.attemptCount += 1
            self.resultLabel.setText(
                f"Invalid number. Attempts left: {3 - self.attemptCount}"
            )
            if self.attemptCount >= 3:
                self.too_many_tries()

    def check_password(self):
        if self.passwordInput.text() == self.final_password:
            self.resultLabel.setText("Password is valid!")
            self.decrypt_and_save_pe()
        else:
            self.attemptCount += 1
            self.resultLabel.setText(f"Invalid. Attempts left: {3 - self.attemptCount}")
            if self.attemptCount >= 3:
                self.too_many_tries()

    def too_many_tries(self):
        self.resultLabel.setText("Too many incorrect attempts. Application will exit.")
        QApplication.quit()

    def decrypt_and_save_pe(self):
        target_dat = "B2C3D4E5.DAT"
        password = self.final_password
        pe_filename = "QDecryptor.exe"
        with open(target_dat, "rb") as f:
            salt = f.read(16)
            init_vec = f.read(16)
            ciphertext = f.read()
        key = PBKDF2(password, salt, dkLen=32)
        aes_cipher = AES.new(key, AES.MODE_CBC, iv=init_vec)
        plaintext = aes_cipher.decrypt(ciphertext)
        pt_last_char = plaintext[-1]
        plaintext = plaintext[:-pt_last_char]
        with open(pe_filename, "wb") as f:
            f.write(plaintext)
        if self.is_valid_PE(pe_filename):
            self.resultLabel.setText("Decryption completed.\nLoader has been saved.")
        else:
            self.resultLabel.setText("Invalid executable file.")
        self.resultLabel.setText("Decryption completed.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = CTFChallenge()
    ex.show()
    sys.exit(app.exec_())
```

It's now clear what `ctf.py` does. A serial number and password are validated, and the correct ones will result in `B2C3D4E5.DAT` decrypted into a PE file. The serial is the current year followed by any character and a md5 hash of the file. The password is hardcoded as `Str34mC1ph3r_0v3rl04d`.

A successful decryption leaves us with `QDecryptor.exe`, and this has us officially in stage 2 of the challenge. DIE tells us that this is a MSVC C/C++ PE file, so back to IDA we go!

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  HANDLE ProcessHeap;
  int i;
  void *g_file;
  LARGE_INTEGER file_size;

  memset(&arg_decrypt, 0, 0x20);
  arg_decrypt = 0;
  encryption_key = 0;
  arg_filename = 0;
  arg_output_filename = 0;
  if ( argc < 2 )
  {
    printf(L"[!] No argument provided. Please pass proper argument. \n");
    return 0;
  }
// this is some next-level argument parsing
// -k is the key
// -i is the input file
// -o is the output file
// -d is the decrypt flag
  for ( i = 1; i < argc && *argv[i] == 45; ++i )
  {
    if ( !wcscmp(argv[i], L"-d") || !wcscmp(argv[i], L"--decrypt") )
    {
      arg_decrypt = 1;
    }
    else if ( !wcscmp(argv[i], L"-k") || !wcscmp(argv[i], L"--key") )
    {
      if ( i + 1 == argc )
      {
        printf(L"[!] Error: missing command specification after -k/--key \n");
        usage();
        return 1;
      }
      encryption_key = argv[++i];
    }
    else if ( !wcscmp(argv[i], L"-i") || !wcscmp(argv[i], L"--in") )
    {
      if ( i + 1 == argc )
      {
        printf(L"[!] Error: Input file is missing \n");
        usage();
        return 1;
      }
      arg_filename = argv[++i];
    }
    else if ( !wcscmp(argv[i], L"-o") || !wcscmp(argv[i], L"--out") )
    {
      if ( i + 1 == argc )
      {
        printf(L"[!] Error: output file path is missing \n");
        usage();
        return 1;
      }
      arg_output_filename = argv[++i];
    }
    else
    {
      printf(L"unknown option \"%s\"\n", argv[i]);
    }
  }
// check to see if inputted key is valid
  if ( !xor_encryption_key(encryption_key) )
  {
    printf(L"[ERROR] Wrong Encryption key\n");
    return 1;
  }
// if there's no output file specified, don't decrypt
  if ( !arg_output_filename )
    return 0;
// sanity check: checks to see if the file contents are normal
// decryption will not proceed if the contents are not what it wants
  if ( !xor_file(arg_filename) )
    return 0;
// check for -d flag before decrypting the file
  if ( arg_decrypt )
  {
    printf(L"[*] Filename: %s\n", arg_filename);
    printf(L"[*] Encryption key: %s\n", encryption_key);
    printf(L"[*] output filename: %s\n", arg_output_filename);
// gets the file size here so if it does the decryption, it knows how much to decrypt
    file_size = get_file_size(arg_filename);
    if ( file_size.QuadPart == -1 )
    {
      printf(L"[!] Error: Unable to get file size or file does not exist.\n");
      return 1;
    }
    g_file = copy_file_mem(arg_filename, file_size.QuadPart);
// this is the decryption function. it does RC4 decryption
    if ( g_file && RC4_decryption_systemfunction032(g_file, encryption_key, file_size.LowPart) )
    {
// write decrypted file out
      if ( arg_output_filename && !WriteFileContent(g_file, file_size.QuadPart, arg_output_filename) )
        printf(L"[!] Error: WriteFileContent.\n");
      printf(L"[*] File has been saved successfully at %s\n", arg_output_filename);
    }
    ProcessHeap = GetProcessHeap();
    HeapFree(ProcessHeap, 0, g_file);
  }
  printf(L"[OK] Process has been done. Exit.\n");
  return 0;
}
```

The following function will check to see if the given file data is what it expects. It will read the file, and do a XOR operation on the file data. If result of the XOR transformation is the same as the file input, then the program knows the input is valid and it will continue to the decryption of the file.

```c
int __fastcall xor_file(const WCHAR *filename)
{
  int i;
  HANDLE hFile;
  DWORD NumberOfBytesRead;
  char file_content[16];

  memset(file_content, 0, sizeof(file_content));
  if ( filename )
  {
    hFile = CreateFileW(filename, GENERIC_READ, 1u, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if ( hFile == -1 )
    {
      p_error(L"CreateFile");
      printf(L"Terminal failure: Unable to open file.\n");
      return 0;
    }
    else
    {
      NumberOfBytesRead = 0;
      if ( ReadFile(hFile, file_content, 0x10, &NumberOfBytesRead, 0) )
      {
// this is the same as the xor_0x3D function. Note that file_data is hardcoded in the program
        for ( i = 0; i < 0x10; ++i )
          file_data[i] ^= 0x3D;                // get file content
        return memcmp(file_content, file_data, 0x10) == 0;
      }
      else
      {
        p_error(L"ReadFile");
        printf(L"Terminal failure: Unable to read file.\n");
        CloseHandle(hFile);
        return 0;
      }
    }
  }
  else
  {
    printf(L"[ERROR] Error Reading file....");
    return 0;
  }
}
```

We have everything we need to decrypt the data! After extracting the data and the key from the PE, we try to decrypt the data in [CyberChef](https://gchq.github.io/CyberChef). What we get back is an empty PNG file. What?

![hex editor output of initial decrypted PNG](/scrambledsquares_1.png)

After some confusion and head-scratching, we realized that because data in the binary is only 16 bytes long, and there was no way this could contain a PNG with any data in it. What about all those `.DAT` files in the original archive? One of those must contain our flag.

`drec` wrote a python script to attempt to decrypt every  `.DAT` file and check to see if it's decryption yielded a valid PNG.

```python
# import Rc4
from Crypto.Cipher import ARC4


def chunks(l, n):
    # Yield successive n-sized chunks from l.
    for i in range(0, len(l), n):
        yield l[i:i + n]


def decrypt(key, ciphertext):
    ret = b''
    cipher = ARC4.new(key)
    for chunk in chunks(ciphertext, 16):
        ret += cipher.decrypt(chunk)
    # ret = cipher.decrypt(ciphertext)
    return ret


def xor_0x3d(a):
    return b''.join([bytes([i ^ 0x3d]) for i in a])


def list_data_files():
    # return list of data files ending with .DAT
    import os
    return [f for f in os.listdir() if f.endswith('.DAT')]


# PNG starts with b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
def is_png(data):
    return b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A' in data


def check_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    # decrypted = decrypt(xor_0x3d(b'Encrypt0r_K3yMast3r!'), data)
    decrypted = decrypt(b'Encrypt0r_K3yMast3r!', data)
    with open(filename + '.png', 'wb') as f:
        f.write(decrypted)
    if is_png(decrypted):
        print('PNG file: {}'.format(filename))
    else:
        print('Not PNG file: {}'.format(filename))

def main():

    dats = list_data_files()

    for dat in dats:
        check_file(dat)



if __name__ == '__main__':
    # sanity check to see if we can decrypt the sample file to a PNG
    # AB 2D 01 8C 6A 8F FD 1F CD 17 63 DB 79 6E 64 06
    # dat = b'\xAB\x2D\x01\x8C\x6A\x8F\xFD\x1F\xCD\x17\x63\xDB\x79\x6E\x64\x06'
    # b'\x96\x10<\xB1W\xB2\xC0\x22\xF0\x2A\x5E\xE6DSY;'
    # wee = decrypt(b'Encrypt0r_K3yMast3r!', xor_0x3d(dat))
    # assert is_png(buff)

    main()

```

Running the script gives us a single hit `2C3D4E5F.DAT`. We open the decrypted PNG, and are met with a QR code.
![qr code](/scrambledsquares_2.png)
A little known tip is that CyberChef can also read QR Codes! By using the `Parse QR Code` feature, we can extract the data, which seems to be base64 encoded

```txt
UEsDBBQAAAAIAIiFJli2E9HCOgAAADAAAAAIAAAAZmlsZS50eHQFQLEKgCAQ/SWDBm9wi2tK8GHcNV6Zg7hF1OcLNH4m9B5Sepqw3q48m6IZ+//stNsSa85wV+O5phAGUEsBAhQAFAAAAAgAiIUmWLYT0cI6AAAAMAAAAAgAAAAAAAAAAAAAAAAAAAAAAGZpbGUudHh0UEsFBgAAAAABAAEANgAAAGAAAAAAAA==
```

![ASCII representation of zip file in cyberchef](/scrambledsquares_3.png)

I instantly recognized the PK bytes here as the magic bytes for the `ZIP` file format. Unzipping the file gives us more base64 encoded data, and de-encoding that leads to the flag! [Here](https://gchq.github.io/CyberChef/#recipe=RC4(%7B'option':'UTF8','string':'Encrypt0r_K3yMast3r!'%7D,'Latin1','Latin1')Parse_QR_Code(false)From_Base64('A-Za-z0-9%2B/%3D',true,false)Unzip('',false)From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=lhA8sVeywCLwKl7mRFNZO9Zm/wIB8R3ZykVHT%2BwdWPzCgeda0NW7%2BReXBDTwThYKTGZt4O2Hbuc6/D6YwwCW0FKLIaHYqYOLusEM7Qo%2Bea4e5SLmFyNdCkrVYDfgEq5MJItfDJUSCi6MjyvQRfB72CRVbCiZdas09kmQOLZlFzj76vuoCPUD0svr3DRwLlTY%2BuuoA4B9ANSSPsGAYKrJzlsP%2B4v0D7xMcsgboM/zdLnBBmZG06I9ok6g54e0HhP9C9OQsO0jL5YbvTmovUv0MxZq/YoHvqYl52Lsz1oc01/jYTSMTvO0PdBe4W2WOnyCW9ZHvkn/wm6V7wFGR0CM8iHAOozqqnogGvO6z4u0XNpUcyCks9apLHUrqxXcJ5YR0khe5Eyh3418lFE00pYSl6YOkvNZ9rTOCOfrodL9uzAlEzpxdSJkIXd/q71Ui%2B7kbwTB8eJRHybO2tXJl8Fqpz1Yo4M47m8cYNnQkKlItLknXML2/pgZHk8JDUirjcjJ3gD6NM2hdu79y7QiOxDf/ALHL6vO%2B5L97UvV0XhyZW/zPHzn9v1wVdwNoNP1QBHUncrcTMz0nvGQ/foQs7e%2BqbglpEMH4uv6KgtiEoxWvWyWad8XA9h2WITAFyauEU9X%2Bbg7YI7b7RhDAgUjNeQVvukbflQ1GLe1TRNpwDAu7D5mSbmYoGvvZ/jj3Fal9UKl4A1VyQwvoUfqlaVkFeUpWz26cag9rvcV2asQWB7yXUsljU52/9JjZBwPc80pcuc97zZeLHzNw7yDg06y/Sg30NNhD3XxfY8Q4RngbUGo8/WO0ZbvEcD2l9Mq6zaBGamnkhGbqYjnzMWOi2oTqrkmDIkx3iPZJKne275suZLC6iP1KYQ4YpS04kKpR8VKdynS2o80PnZDpWSska4hbjj2dxtg7QLu3lM0LFHaa0KH3psTAoRlg/IAWEVbvz6vjWtHxIW/xxLLoMV90CJ6YfqUgftH6IhYatRP9hx4hRP3QZoSQ%2BqOAxN6DS6i8tUXVwOSLwlHcdcV2rMtzLwtqI/i8fSemUmADyre9ptiTHMooVbi5ED9Fi2MAGodKyC/q2S2vsgwYbh3wrhTx9sc1nhwyRThik8Nqt2DFegogBp6/wmIk4TKX4v9/HciO2vH1XPlL9vR7vHv8j760JcEvGCXMbixU64gYkW71ZtCloWC4eKDpi1uwC7ZnXuMBfEhHMC6Yaj4vrZhRBo9K683wTiyO%2B4cxOc0t86Fbxwyb7j%2BG1wx4/R2WTQcEiDO003kCo8kM6%2BAxZq6mPYscg%2B/W5Bby8wUZGUgyNQQneasM3Vi7IYX2%2BOl5RDe5s6DIdCQzHXKhzI6NZs8VaqRI7E2iKTb1RjNboPR8t38GpgNnNa%2BYr5QcqzztsmJd27uQZNF9/vYephD1fVhaG3IYXVE4WaacaArDmlMGr0xBDB9RfZWsMIDrqag3gH7SOc/iIdGCiyaoRoZlKLWxsmB/VCy9bgRvYdHaWWZWvbvaDO4OJ%2BocvV5Qm/qVUtkJYfQcs39igwsC28TiP2YvbLmzX/Lgm9Is%2Bwt3cqeAfgrYWq8WJHDdHgEKXhGpNAySzsAf3M8tPN8InNqaC7bnBeN5MrEntvPMrd0Xnre8yn/GwkIcaieO8vVi6jgAQIl0nm3ICHW%2ByB%2BMQxnLtF0adMuvZA0jpuYlHnqwy%2BBmG3C97uRkmaeX89jhr3AX9Z%2BJd15fxX7H7AQ8OhY4Yeu82SrphMjZ3HxMBgNx%2BC1E0jVgZJIUuWQimK5vu2162RbklxD6MSthHW8t2sFju7C6F50PSWTILDSVHiSojOkoqgjXb%2BIuZhOqSP1psY3oK0gWkez68VqNyABJtJDHz14wPA/XG9T928aka1kL9U5xwu4RM8YhmB2Lj3xaYU2tCPhNdpN9jxB27k9DAVIbM4DtX/Uk26CigEEI2cYav4LMyo8ttHNr21NAYhjjr3zdoUsG7xGinQCqUhhfXDSjUuQisx9LHP0TY3simYh9ujUweDIzW4sOczeiOWPCOL%2B3MZ3ickeMBqgGEEebfdYDq5iIoIF0L4s4awYdW4GnpIiPT%2BVDqodYgXI3CrqrQEjpZDzohjkeoGJLuCzzqeE6feEODDrVawuHZUngIii8qUYLwOWs/M8JN3w2JoCRUPX3HqafOnMB9QVajublb1JkNnlYfNRLfT/EM3g6SE) is the full CyberChef chain.

`EspionageCTF{Gl1tch_1n_Th3_M4tr1x}`

## Conclusion

I hope you enjoyed my writeup and learnt something from it! Props to the challenge authors and ISSessions for hosting the CTF.
