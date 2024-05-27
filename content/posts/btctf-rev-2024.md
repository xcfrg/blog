---
author: "fastcall"
title: "BTCTF 2024 golang2 rev challenge writeup"
date: "2024-05-26"
description: "at least it's not rust"
summary: "A writeup for the Go reverse engineering challenge in BTCTF 2024."
tags: ["re", "ctf", "go"]
categories: ["writeups"]
ShowToc: true
draft: false
---
Teammates:
- `0x41*32`: web, osint
- `SuperBeetleGamer`: crypto, foren
- `fastcall (me!)`: rev, foren

## Solution

We came first place at BTCTF 2024 and as requested, this is my writeup for the golang2 rev challenge.

The original binary for this challenge was a stripped MACH-O mac binary. 
![mach-o binary in die](/btctf2024-die.png)

I spent quite a lot of time looking at this, and if you are also looking at stripped Golang binaries, the following tooling may be helpful:

- [AlphaGolang](https://github.com/SentineLabs/AlphaGolang) - Juan Andres Guerrero-Saade at SentinelLabs created these awesome IDA scripts to help label and retype everything in the Golang standard library, as go is usually statically linked. Unfortunately, I couldn't get the parts of the scripts to work with my newer IDA version, and IDA improved it's metadata detection significantly in later versions. This is still useful if you have an old version, and a blog post on how its even possible to recover function names from a "stripped" Golang binary may be on its way👀👀👀.
- [GoReSym](https://github.com/mandiant/GoReSym)- This tool by Mandiant attempts to achieve almost the same thing, but is more up to date and has scripts for both IDA and Ghidra. I ended up not needing to use it for this challenge, but it may be useful in the future.

Just as `0x41*32` was about to spin up a mac OS VM on his VPS for me to use the IDA debug server with, the organizers updated the challenge with a new binary, compiled for Linux this time.

After talking to the organizers at the end of the CTF, I found out that one of the important functions got compiled out and was never in the original binary to begin with. (don't you guys test these? )

After loading the binary into IDA, we get a nice surprise:
![debug info!](/btctf2024-dwarf.png)
*DEBUG INFO?*

I don't know if this was intentional or not, but the Linux binary was not stripped. Unlike on other platforms (Windows uses .pdb files, mac OS stores debug info in either object files or .dsym files), Linux debug information comes attached to the binary, which does lead to a lot of scenarios where it's debug info is shipped to production, and not just with CTFs.

In Golang binaries, `main_main()` is always the real entry point, so lets jump there and begin reverse engineering.

```cpp
  tcp_str.str = (uint8 *)"tcp";
  tcp_str.len = 3LL;
  ip_str.str = (uint8 *)"137.184.106.142:1337";
  ip_str.len = 20LL;
  conn = net_Dial(tcp_str, ip_str);
  w.len = (int)conn._r0.data;
  v22.data = conn._r0.tab;
  if ( conn._r1.tab )
  {
    a_16 = v1;
    a[0] = &RTYPE_string_0;
    a[1] = &Error_connecting_to_server; // Error connecting to server:
    *(_QWORD *)&a_16 = conn._r1.tab->_type;
    *((_QWORD *)&a_16 + 1) = conn._r1.data;
    stdout.data = os_Stdout;
    stdout.tab = (runtime_itab *)&go_itab__ptr_os_File_comma_io_Writer;
    error_connecting_to_server_str.array = (interface_ *)a;
    error_connecting_to_server_str.len = 2LL;
    error_connecting_to_server_str.cap = 2LL;
    fmt_Fprintln(stdout, error_connecting_to_server_str);
    os_Exit(1LL);
    conn._r0.tab = (runtime_itab *)v22.data;
    conn._r0.data = (void *)w.len;
  }
```

I saw this call to `net_Dial()`, and after looking at the [documentation](https://pkg.go.dev/net), I realized that the binary was talking to the server on a low level tcp interface, quite similar to `netcat`. Testing my theory, I tried to connect to the server and I was indeed successful!

```
$ nc 137.184.106.142 1337
give password:

Access denied
```

```cpp
  connected_str_16 = v1;
  connected_str[0] = &RTYPE_string_0;
  connected_str[1] = &Connected_toserverat; // Connected to server at
  ip_str_2.str = (uint8 *)"137.184.106.142:1337";
  ip_str_2.len = 20LL;
  ip_str_2.str = (uint8 *)runtime_convTstring(ip_str_2);
  *(_QWORD *)&connected_str_16 = &RTYPE_string_0;
  *((_QWORD *)&connected_str_16 + 1) = ip_str_2.str;
  ip_str_2.len = (int)os_Stdout;
  ip_str_2.str = (uint8 *)&go_itab__ptr_os_File_comma_io_Writer;
  connected_str_1.len = 2LL;
  connected_str_1.cap = 2LL;
  connected_str_1.array = (interface_ *)connected_str;
  fmt_Fprintln((io_Writer)ip_str_2, connected_str_1);
  main_store_password();
```

Huh, that `main_store_password()` function sure like it may have that password...

```cpp
password_str.array = (uint8 *)runtime_newobject((internal_abi_Type *)&RTYPE__20_uint8);
  qmemcpy(password_str.array, "super_duper_password", 20);
  password_str.len = 20LL;
  password_str.cap = 20LL;
  a.array = (interface_ *)&RTYPE__slice_uint8_0;
  a.len = (int)runtime_convTslice(password_str);
  password_str.len = (int)os_Stdout;
  password_str.array = (uint8 *)&go_itab__ptr_os_File_comma_io_Writer;
  password_str.cap = (int)&a;
  v1 = 1LL;
  v2 = 1LL;
  fmt_Fprintln(*(io_Writer *)&password_str.array, *(_slice_interface_ *)&password_str.cap);
```

Plaintext? Wait what?

```
password = rax                          ; _slice_uint8
mov     dword ptr [password], 65707573h ; epus
mov     rcx, 5F72657075645F72h          ; _repud_r
mov     [password+4], rcx
mov     rcx, 64726F7773736170h          ; drowssap
mov     [password+0Ch], rcx
```

The password is passed as an immediate value in a stack string like format, however IDA detects this pattern and outlines the instructions into a `memcpy()`.

After entering password into the server:

```
$ nc 137.184.106.142 1337
give password:super_duper_password
super_duper_password
btctf{f0und_th3_g0ph3r_h0le}
```

We get the flag! Why doesn't this have more solves...
`btctf{f0und_th3_g0ph3r_h0le}`

## Post-mortem

So turns out, after I downloaded the binary but before other people did, organizers swapped the binary with one that is unsolvable. 

Thanks to lolmenow for the following timeline:

**TIMELINE OF GOLANG2** Episode 1: Disaster strikes upon BTCTF

**[05/24/2024 11pm EST]** A new challenge titled *golang2* was released after all the pwn challenges went down.

**[05/25/2024 12:28am EST]** JP, an organizer, compiled the binary incorrectly. A new linux version was swapped.  


**[05/25/24 12:30am EST]** fastcall downloads the binary and starts reversing.

**[UNKNOWN TIME] Somehow, the binary was silently swapped. The time and date is still unknown.**

**[05/25/24 12:42am EST]** A team titled ".;,;. But Canadian" was the first team to solve the challenge, specifically fastcall.

**[05/25/24 10:00:41 IST]** Somehow, the binary was swapped twice! With a user Abhi having a different file then everyone else had.


**[05/25-05/26]** Chaos ensues as no other team is able to solve it.

**[05/26/2024 4:00pm]** CTF ends and fastcall publishes the writeup for the challenge.

**[05/26/2024 4:23pm]** fastcall realizes that the binary was swapped and notifies everyone. He then uploads the correct binary.

**[05/26/2024 4:30pm]** Everyone who attempted to solve this problem realizes the error.

**[05/26/2024-PRESENT]** Everyone complains about the challenge. Nothing can be done.

