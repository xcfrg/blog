---
author: "fastcall"
title: "ISSessions Black Hat Bureau CTF 2025 RE challenge writeups"
date: "2025-02-16"
description: "i <3 guessing"
summary: "Write-ups for all the reverse engineering challenges in ISSessions CTF 2025."
tags: ["re", "ctf"]
categories: ["writeups"]
ShowToc: true
draft: false
---
Here's are all my writeups for all of the reverse engineering challenges in Black Hat Bureau CTF 2025.

UofTCTF Members:
- \_\_fastcall (me): rev
- White: pwn
- Toadytop: cryptography
- SteakEnthusiast: web

**NOTE: Once again, all code in writeup has been beautified manually for your reading pleasure. It may not represent the exact disassembly, but it does represent the semantics of the code.**

## SIMPLE DIMPLE (19 solves)

>this is a very simple dimple challenge

We get two zip files, one with an executable with linux, and one for windows. Decompiling the linux executable...

```c
int main(int argc, const char **argv, const char **envp)
{
  char flag_buffer[64];
  char flag[20];
  char password[12];
  char input[32];

  strcpy(password, "sup3rs3cr3t");
  strcpy(flag, "bhbureau{$+R!nGz}");
  strcpy(flag_buffer, flag);
  printf("Enter the password: ");
  scanf("%s", input);
  if ( !strcmp(input, password) )
    printf("Access Granted! Flag: %s\n", flag_buffer);
  else
    puts("Access Denied!");
  return 0;
}```

The flag is visible in plaintext. `bhbureau{$+R!nGz}`
## Starlight's Nightmare (13 solves)

>**He likes.. Cool cats..** *Phantom Maze, Tackle this short-but-twisted reverse engineering puzzle. A secret hidden, protected Uncover the correct password, decrypt the hidden key, and call the victory function to reveal the final flag. Good luck.*

After completely ignoring the description or ascii art cat, we look at the at the main function of the ELF binary we are given...

```c
int main(int argc, const char **argv, const char **envp)
{
  char key[64];
  char input2[40];
  size_t size;
  char xored_key[32];
  char input[40];
  void (*indirect_call)(void);

  size = 0LL;
  combineKeys(key, 64uLL);
  printf("Enter password: ");
  fgets(input, 32, _bss_start);
  input[strcspn(input, "\n")] = 0;
  if ( !strcmp(input, "UnbreakableP@ssw0rd!") )
  {
    puts("Correct password! Generating encrypted key...");
    xor_encrypt(key, xored_key, &size);
    printf("Encrypted Key (HEX): ");
    for ( size_t i = 0; i < size; ++i )
      printf("%02X", xored_key[i]);
    putchar('\n');
    indirect_call = (globalFnPtrOffset - 5);
    printf("Now enter the decrypted key: ");
    fgets(input2, 32, _bss_start);
    input2[strcspn(input2, "\n")] = 0;
    if ( !strcmp(input2, key) )
      indirect_call();
    else
      puts("Wrong decrypted key! Try harder.");
    return 0;
  }
  else
  {
    puts("Incorrect password. Exiting...");
    return 1;
  }
}
```

That `indirect_call()` after the second successful `strcmp` seems suspicious! Let's see where that function pointer goes:

```
.data:4078                 public function_ptr
.data:4078 function_ptr    dq offset loc_11BD+1
```

`loc_11BD` goes to a function called`win()`, with the flag visible in plaintext, with no flag format.

```c
int win()
{
  return puts("Congratulations! You have solved the challenge! Here is your flag: W3bIsCool-But-R3VEng-istoo");
}
```

## Eleet (6 solves)

> Agent we found this program "Eleet" on one our local computers, our analysis has determined it to be harmless but it seems one of your colleagues likes to play pranks. Your task is to figure out what they have hidden in the binary for you.

We find ourselves with a unstripped ELF C binary, and before actually we RE the whole binary, I always like just by looking around at the binary to see if I can find a shortcut or a unintended solution. I am immediately alerted to the interesting sounding `decrypt_flag` function...

```c
void decrypt_flag(char *out_flag)
{
  for ( int i = 0; i < 31; ++i )
    out_flag[i] = encoded_flag[i] ^ 0x42;
  out_flag[31] = 0;
}
```

```
.data:4090     ; char encoded_flag[31]
.data:4090     encoded_flag    db 20h, 2Ah, 20h, 37h, 30h, 27h, 23h, 37h, 1, 16h, 4, 39h
.data:409C                     db 7, 3Ah, 32h, 2Eh, 2Dh, 2Bh, 36h, 27h, 26h, 1Dh, 0, 23h
.data:40A8                     db 21h, 29h, 26h, 2 dup(2Dh), 30h, 3Fh
```

We find that the flag is sitting directly in the executable, behind a 1 byte XOR. IDA doesn't have the best UX when it comes to copying bytes out of it's views (select the bytes you want, Edit -> Export Data and copy it out of the preview box), and [hexcopy](https://github.com/OALabs/hexcopy-ida) by [OALabs](https://www.openanalysis.net/), is a great way to turn it into a single click experience. I used CyberChef to do the decryption. `bhbureauCTF{Exploited_Backdoor}`

## tseuqer (5 solves)

> We have reason to believe the bureaus agents have poined our File Integrity Checker, tseuqer. This has been serious breach due to the software being very popular with our staff. We want you to find the leak and remedy is as soon as possible.

We find a ELF binary written in C with a main function that creates a pthread. Let's look at the created thread...

```c
void* main_thread(void *ptr)
{
  FILE *fHandleNull;
  char url[264];
  CURL* handle;

  base64_decode("aHR0cHM6Ly9p[c2Nlc3Npb25zY3RmLXF3ZXJ0eXh6cXdlcnR0eS5jaGFscy5pby8=", url);
  while ( 1 )
  {
    do
    {
      sleep(10u);
      handle = curl_easy_init();
    }
    curl_easy_setopt(handle, CURLOPT_URL, url);
    curl_easy_setopt(handle, CURLOPT_NOBODY, 1L); // do not get the body (HEAD request) 
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, 5L); // set max transfer time to 5 seconds
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, ); // disable peer verification
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L); // disable certificate host verification
    curl_easy_setopt(handle, CURLOPT_VERBOSE, 0L); // verbose mode is disabled by default, this does nothing
    fHandleNull = fopen("/dev/null", "w");
    curl_easy_setopt(handle, CURLOPT_STDERR, fHandleNull);
    curl_easy_perform(handle);
    curl_easy_cleanup(handle);
  }
}
```

After decoding the base64 string, we get the URL, `https://iscessionsctf-qwertyxzqwertty.chals.io/`. The challenge author made a typo when creating the challenge, and so we guess the correct URL `https://issessionsctf-qwertyxzqwertty.chals.io/`. Visiting this URL in a browser gives us the flag (emulating the cURL request will not help as it specifically does not get the body). `bhbureauCTF{H4ck3r_H34rtb34t_St0pp3d}` 

## Launch Codes (2 solves)

> Operative, we have gotten our hands on a top secret application which is rumoured to contain an active launch code for one of the cold war era ICBMs. Intelligence suggests that the program verifies an ID related to historic military technology, but all further details are classified. We would like you to recover the active code from this application before the bureau gets their hands on it.

We get a PE file `LaunchCodes.exe`, after putting it through DIE, we find out that it's written in [nim](https://nim-lang.org)! This language has become popular with threat actors in recent years, and so there is some [nice reverse engineering tooling](https://www.welivesecurity.com/en/eset-research/introducing-nimfilt-reverse-engineering-tool-nim-compiled-binaries/) available for us to use. Unfortunately, when trying to use nimflit for the latest version of IDA Pro (9.0sp1), we find the plugin to consistently enter an infinite loop. I unfortunately had to use [ghidra](https://ghidra-sre.org/) for the rest of this challenge :(  

```
$ LaunchCodes.exe
------------------------------------------------------------
                Welcome to ICBM control system
------------------------------------------------------------
Enter your secret key:
```

Running the program, we see prompt that asks for a secret key.

```c
std::syncio::readLine(&local_38,(FILE *)pFVar2);
if (*local_20 == '\0') {
        local_58 = 0xa5;
        local_128 = local_38;
        local_120 = local_30;
        local_28 = chk(&local_128);
// { ... }
```

Looking around in the main function for a bit, we see a `readline` call, followed by a call to a user create function called `chk` (check?). This is a complicated function, however what is does it a nutshell is hash the input provided by the user (by calling digest from the `nimcrypto` library, and then enter one of two comparison checks.

Before fully reversing this function, let's see what happens when we inverse these checks. 

![x64dbg picture](/x64dbg_3.png)
We place a breakpoint in x64dbg at the first of these checks, inverse the [ZF flag](https://en.wikipedia.org/wiki/Zero_flag), so the `jne` instruction will jump to the other branch, and we find that the flag is printed out, with no flag format. `Your requested resource is: {S3COND_S7RIKE}`
## Evasive (broken, 2 solves)

> The Black Hat Bureau has developed a new tool to guard their secrets with ruthless precision. It has been code named Evasive due to its highly volatile behavior. We want you to uncover the secret it hides.

```c
int main(int argc, const char **argv, const char **envp)
{
  char out_str[32];
  char input[32];

  anti_debug();
  timing_check();
  printf("Enter the flag: ");
  fgets(input, 32, _bss_start);
  input[strcspn(input, "\n")] = 0;
  if ( check_key(input) )
  {
    decrypt_flag(out_str);
    printf("Correct! Flag is: %s\n", out_str);
  }
  else
  {
    puts("Incorrect flag!");
  }
  return 0;
}
```

We are given another ELF binary, that seems to be a flag checker.

```c
char *decrypt_flag(char *out_str)
{
  char *result;
  int i;

  for ( i = 0; i <= 30; ++i )
  {
    result = &out_str[i];
    *result = flag_encrypted[i] ^ 0x7A;
  }
  return result;
}
```

Working backwards, we check the `decrypt_flag` function, where we see a similar routine as in `Eleet`. Is this another 1 byte XOR protecting the flag?

```
00000000  62 68 62 75 72 65 61 75 43 54 46 7b 1f 3f 53 33  |bhbureauCTF{.?S3|
00000010  63 72 23 74 55 6e 76 33 22 6c 33 64 78 2d 7d     |cr#tUnv3"l3dx-}|
```

Not quite, after decrypting the flag, we find it to have some corrupted characters. `bhbureauCTF{..S3cr#tUnv3"l3dx-}` Weird, lets look at the other function...

```c
bool check_key(const char *input)
{
  char v2[36];
  int j;
  int checksum;
  int i;

  if ( strlen(input) != 31 )
    return 0;
  if ( strncmp(input, "bhbureauCTF{", 12) )
    return 0;
  for ( i = 12; i <= 29; ++i )
    v2[i] = (7 * i % 256) ^ input[i];
  checksum = 0;
  for ( j = 12; j <= 29; ++j )
    checksum += (j + 1) * v2[j];
  return checksum == -10441;
}
```

We see a checksum being generated and used as a constraint on the input. The first thought you might have would be to try to use the checksum and solve for the corrupted characters with a symbolic solver like [z3](https://github.com/Z3Prover/z3). 

But after looking at this function and at the flag carefully, we notice a *huge problem*, the constraints are not well defined enough to find a single ASCII solution. Our checksum is only 4 bytes long (size of an int), and [our flag is much longer than that](https://en.wikipedia.org/wiki/Pigeonhole_principle). **There are hundreds of thousands of valid ASCII flags that pass this checksum and are considered a valid check by the program.**

However, this challenge, while broken, we still solved. How? Guessing.

`bhbureauCTF{?S3cr#tUnv3"l3dx-}`
Looking at the corrupted flag, we can guess some of the more obvious corrupted characters. We can replace the `#` with a `3`, and the `"` with a `1`. We also need to guess that the character set is `[a-zA-Z0-9\-]`, as there will still be many valid ASCII solutions.

We then replace both of the corrupted characters left with `?` to indicate to our script that we need to solve for them.

```python
import z3

flag = bytearray(b'??S3cr3tUnv31l3dx-')
flagOrig = bytes(flag)

for i in range(len(flag)):
    flag[i] ^= 7 * (0xc + i)

flagEnc = [int.from_bytes(bytes([i]), 'little', signed=True) for i in flag]

flagVars = [z3.BitVec(f'f{i}', 8) for i in range(len(flag))]

s = z3.Solver()
for ind, c in enumerate(flagOrig):
    if c != b'?'[0]:
        s.add(flagVars[ind] == flagEnc[ind])
    else:
        s.add(z3.Or(z3.And((flagVars[ind] ^ (7 * (0xc + ind))) <= 57, (flagVars[ind] ^ (7 * (0xc + ind))) >= 45),
                    z3.And((flagVars[ind] ^ (7 * (0xc + ind))) <= 90, (flagVars[ind] ^ (7 * (0xc + ind))) >= 65),
                    z3.And((flagVars[ind] ^ (7 * (0xc + ind))) <= 122, (flagVars[ind] ^ (7 * (0xc + ind))) >= 97)))

csum = 0
for i in range(len(flagEnc)):
    csum += z3.SignExt(8, flagVars[i]) * (1 + 0xc + i)

s.add(csum == z3.BitVecVal(-10441, 16))

while s.check() == z3.sat:
    solution = False
    m = s.model()
    for i in flagVars:
        solution = z3.Or((i != m[i]), solution)
    s.add(solution)
    realFlag = b''
    for i in flagVars:
        realFlag += (m[i].as_long()).to_bytes(1, 'little')
    for i in range(len(flag)):
        flag[i] = realFlag[i] ^ (7 * (0xc + i))
    print(flag) # output: bytearray(b'InS3cr3tUnv31l3dx-')

```

`bhbureauCTF{InS3cr3tUnv31l3dx-}`
## Piece of the Pie (1 solve)

> Operative, this seemingly plain looking calculator program is believed to be hiding a critical piece of information which can severely damage our field operations. Find the hidden piece and report back ASAP.

A C++ binary, wonderful! I noticed immediately that it was a C++ binary from some of the default exception code & strings from `std::string` functions. (`basic_string: construction from null is not valid'`, etc.) 

We can find the main function by searching for the text that appears when running the executable. This leads to a very long main function, I have extracted out some of the  interesting parts...

```c
  v3 = (std::operator<<<std::char_traits<char>>)(&std::cout, "+++++++++++++++++++++++++++++++++++++++++++++++");
  (std::ostream::operator<<)(v3, &std::endl<char,std::char_traits<char>>);
  v4 = (std::operator<<<std::char_traits<char>>)(&std::cout);// ++++++++++ Basic Integer Calculator +++++++++++
  (std::ostream::operator<<)(v4, &std::endl<char,std::char_traits<char>>);
  v5 = (std::operator<<<std::char_traits<char>>)(&std::cout);// +++++++++++++++++++++++++++++++++++++++++++++++
  (std::ostream::operator<<)(v5, &std::endl<char,std::char_traits<char>>);
```

This the initial banner outputted to the terminal. You may notice that the C++ library functions in this binary look nothing like the ones you would actually use in your code. This is because a majority of the standard library is heavily templated, and most of it is optimized out at compile time.

```c
  v82 = &v72;
  combine_str(v65, "NsaW", &v72);
  combine_str(&v66, "IsjI", &v72);
  combine_str(&v67, "*&sda==", &v72);
  (sub_403568)(&v72);
  v81 = &v73;
  combine_str(v61, "ZGR", &v73);
  combine_str(&v62, "JSA==", &v73);
  combine_str(&v63, "ya00", &v73);
  combine_str(&v64, "4fQ==", &v73);
  (sub_403568)(&v73);
  v80 = &v74;
  combine_str(v58, "XcVy", &v74);
  combine_str(&v59, "asFj", &v74);
  combine_str(&v60, "4fQ==", &v74);
  (sub_403568)(&v74);
  v79 = &v75;
  combine_str(v54, "DeP", &v75);
  combine_str(&v55, "He", &v75);
  combine_str(&v56, "X0d", &v75);
  combine_str(&v57, "eXJv", &v75);
  (sub_403568)(&v75);
  v78 = &v76;
  combine_str(v51, "bTNN", &v76);
  combine_str(&v52, "X2", &v76);
  combine_str(&v53, "4z", &v76);
  (sub_403568)(&v76);
  *&v77[1] = v77;
  combine_str(v48, "XDyFcv", v77);
  combine_str(&v49, "asFDasj", v77);
  combine_str(&v50, "4fFGQ==GA", v77);
  (sub_403568)(v77);
```

Looks to be a base64 string assembled out of order by that function.

```c
(std::operator<<<std::char_traits<char>>)(&std::cout, "Enter your expression ([num1][+|-|*|/][num2]): ");
v25 = (std::istream::operator>>)(&std::cin, &v71);
v99 = &math_operator;
v26 = (std::operator>><char,std::char_traits<char>>)(v25);
(std::istream::operator>>)(v26, &v70);
if ( math_operator == '/' ) {
    v36 = (std::operator<<<std::char_traits<char>>)(&std::cout, "Result: ");
    v37 = sub_4022DE(v71, v70);
    v38 = (std::ostream::operator<<)(v36, v37);
    (std::ostream::operator<<)(v38, &std::endl<char,std::char_traits<char>>);
    } else {
		// { ... }, for all basic operators +, -, *, /
		goto JUMP_TO_INCREMENT;
    }
JUMP_TO_INCREMENT:
        ++increment_to_winapi_calls;
```

Just your average basic calculator...

```c
if ( increment_to_winapi_calls == 2 ) {
    CurrentProcessId = GetCurrentProcessId();
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, CurrentProcessId);
    if ( hProcess ) {
	    // { ... } some string operations
	    mem_size = (std::string::size)(written_memory);
        mem_str = (std::string::c_str)(written_memory);
	    lpBaseAddress = VirtualAllocEx(hProcess, NULL, mem_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(hProcess, lpBaseAddress, mem_str, mem_size, NULL);
        hHandle = CreateRemoteThread(hProcess, NULL, 0, lpBaseAddress, NULL, 0, NULL);
        WaitForSingleObject(hHandle, 12);
        VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
        CloseHandle(hHandle);
        CloseHandle(hProcess);
        ++increment_to_winapi_calls;
        (std::string::~string)(written_memory);
    }
    
```

With a little secret! On the second iteration of the loop (your second calculation made), a hidden code path will execute some winapi calls using the aforementioned decrypted string.

I switched to `x64dbg` to see what the reassembled string was in memory without having to reverse the `combine_str` function. Placing a breakpoint on the WriteProcessMemory function...
![x64dbg picture](/x64dbg_1.png)
We can see the base64 string in memory, [decoding and reversing](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,true)Reverse('Byte')&input=RGVQSGVYMGRlWEp2YlROTlgyNHpaR1JKU0E9PQ&oeol=CR) it gives us the flag without the flag format, again... `bhbureauCTF{HIdd3n_M3mory}`

## Sneaky (1 solve)

> Operative, we have recieved a suspicious executable, it seems to be erratic in behaviour. We have reason to belive one of our undercover agents embedded critical information in it. Analyse the behavior and retrieve the information. Good Luck!

In this challenge we get both a C binary that calls a provided DLL with exported functions. The DLL is largely irrelevant to my solve, and the only function of any significance in it is a function that does a single byte XOR.

In the main function, we see a random number being generated and passed into another function.

```c
if ( random_num == 4 ) {
	CreateFileW(L"sneak100.exe", GENERIC_ALL, FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
	fileHandle = fopen("sneak100.exe", "wb");
    if ( !fileHandle )
      exit(1);
    fwrite(&unk_403020, 1u, count, fileHandle);
    fclose(fileHandle);
    free(Block);
}
```

If the random number generated is 4, the binary will write something that appears to be an executable to disk. During the CTF, I opted to extract this binary with a debugger in case there was any decryption done that I missed, but after some post analysis, it should be fine to rip out the binary straight from IDA. Make sure to switch to the hex view though, as IDA seems to accidentally try to disassemble the raw binary file.

After we've extracted out new PE file, its time to put it back into IDA! Our main function looks *interesting* to say the least:

```c
int main(int argc, const char **argv, const char **envp)
{
  tmain();
  if ( MessageBoxA(
         NULL,
         "hewwo, hii there! welcome to absolutely not shady malware >w<",
         "helpa >w<'",
         MB_ICONINFORMATION | MB_YESNO) == IDYES )
    MessageBoxA(NULL, "hewwo, cutie x3\ni suggest you twy jumping awound > :3", "helpa > w < '", MB_ICONINFORMATION);
  else
    MessageBoxA(
      NULL,
      "h-hewwo, pwease don't ignore me x3  i-i'll twy my best to help you, i pwomise :3 pwease give me a chance to show y"
      "ou >///< i-i weawwy want to be thewe fow you, pwease x3",
      "helpa > w < '",
      MB_ICONINFORMATION);
  ShellExecuteW(NULL, open, "c", L"/c del /A \"sneak100.exe\"", NULL, 0);
  return 0;
}
```

There's no other calls or jumps from main, and no interesting [TLS callbacks](https://learn.microsoft.com/en-us/cpp/build/reference/tls?view=msvc-170)(code that runs before the main function), other than the default ones generated by MinGW binaries. For once, we will actually take some advice from the challenge and look around the binary.
![ida picture](/ida_1.png)

In the `.rdata` section (read only data), we discover instructions that were disassembled by ida, but not marked as a function, likely because they aren't in the `.text` section (section for executable code) and are never actually loaded or executed.

We can easily tell this is a function due to the [function prologue](https://en.wikipedia.org/wiki/Function_prologue_and_epilogue), but before decompiling the code, we need to mark it as a function in IDA with the `P` hotkey.

```c
int hidden_function() {
	// { ... }
	strcpy(v5, "C:\\Windows\\System32\\cmd.exe /c \"j6lLbJ5vxcyTpzFBeeU6UkQMIeqqRBM3\" > flag.txt");
	return (v4)(v5, 10);
}
```

The function has a lot going on, but at the bottom of the function, we see that IDA has inlined a `strcpy` that is in the format to be executed by `ShellExecuteW`. It writes `j6lLbJ5vxcyTpzFBeeU6UkQMIeqqRBM3` to `flag.txt`, and so I assumed that was the flag (after adding the flag format), but this was incorrect.

To my knowledge, the flag is not decrypted any further than this, so it's time to *guess the encoding*! To make an educated guess, we use the [dcod.fr cipher identifier](https://www.dcode.fr/cipher-identifier). 

![dcode.fr](dcodefr_cipher_guessing_1.png)

The cipher is identified as base62, and we can also use dcode to decode it. We get `Cookie_FOR_your_hardWork`, our fourth flag with no flag format!
## Phantom Protocol (broken, 0 solves)

> The Black Hat Bureau seems to have found another target in a commonly used developer application, MySQL DB. We have had to suspend all our database server operations, we believe the bureau has planned something big this time and whatever it is, its very dangerous for us. We want you to analyse the application and see if anyone breached any of our user accounts over at [https://issessionsctf-secure-login.chals.io](https://issessionsctf-secure-login.chals.io)

### Initial Attempt

Looking at the site first, it's just a very basic login form. There's nothing else here so let's look at the binary. 

We are greeted with a pretty large PE file, 23MB. upon further inspection, it looks like a self contained .NET bundle. A perfect excuse to use [AsmResolver](https://github.com/Washi1337/AsmResolver), a wonderful library for modifying PE and .NET files!

```csharp
using AsmResolver.DotNet.Bundles;
  
class Program  
{  
    static void Main(string[] args) {
	    if (args.Length <= 0) return;  
	    var manifest = BundleManifest.FromFile(args[0]);  
	    foreach (var file in manifest.Files) {
		    var path = file.RelativePath;  
	        var contents = file.GetData();
	        Console.WriteLine($"Extracting {path}...");
	        File.WriteAllBytes($"extracted/{path}", contents);  
	    }
	}
}
```

We can extract all the files with the help of the manifest included in the binary.

```
Extracting MySQLdb.dll...
Extracting MySQLdb.runtimeconfig.json...
Extracting Microsoft.Windows.SDK.NET.dll...
Extracting WinRT.Runtime.dll...
Extracting MySQLdb.deps.json...
```

Analyzing the .NET binary with dnSpyEX, we can instantly see what looks to be a implementation of a widely known process injection trick, [process hollowing](https://red-team-sncf.github.io/complete-process-hollowing.html). A suspended process is created with `C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe` but that processes memory is replaced by a different PE that is mapped into memory.

The goal was simple, place a breakpoint on the last `WriteProcessMemory` call and extract the PE from memory. There's a problem though!

```csharp
public static void Main(string[] args) {
	if (Debugger.IsAttached) {
		Environment.Exit(1);
	}
	mySQL.ntM.MsgBox(IntPtr.Zero, "Incompatible MySQL Version!!", "ERROR", 16U);
	Stopwatch stopwatch = Stopwatch.StartNew();
	Thread.Sleep(100);
	stopwatch.Stop();
	if (stopwatch.ElapsedMilliseconds > 110L) {
		Environment.Exit(1);
	}
// { ... }
```

Under normal conditions, the binary will always exit before getting to the process hollowing. My solution? patch it out!

![dnspy picture](/dnspyex_1.png)

By hitting `Edit IL instructions` in the context menu for the main function, we can see that the anti debug and timing checks are implemented in 20 IL instructions. We could patch these out using dnSpyEx, but we might as well get some AsmResolver usage in:

```csharp
using AsmResolver.DotNet;
using AsmResolver.DotNet.Bundles;

namespace ISSessionsCTF2025_PhantomProtocol;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length <= 0) return;
        var manifest = BundleManifest.FromFile(args[0]);

        var mainFile = manifest.Files.First(); // the first file in the bundle is our managed DLL!
        
        var assembly = AssemblyDefinition.FromBytes(mainFile.GetData());
        
        // get the instructions for the entrypoint (the Main() method)
        var mainMethod = assembly.Modules[0].ManagedEntryPointMethod;
        if (mainMethod?.CilMethodBody == null ) return;
        var instructions = mainMethod.CilMethodBody.Instructions;

        for (int i = 0; i < 21; i++)
        {
            instructions[i].ReplaceWithNop(); // the first twenty instructions are for the antidbg and timing checks
        }
        
        // verify instructions look correct
        // var formatter = new CilInstructionFormatter();
        // foreach (var instruction in instructions)
        //     Console.WriteLine(formatter.FormatInstruction(instruction));

        assembly.Write("out/patched.dll");

        var newFile = new BundleFile(
            relativePath: "MySQLdb.dll",
            type: BundleFileType.Assembly,
            contents: File.ReadAllBytes("out/patched.dll"));

        manifest.Files.Remove(mainFile);
        manifest.Files.Add(newFile);
        
        // replace file in the bundle with the patched out, write new bundle to the filesystem

        manifest.WriteUsingTemplate(@"out\apphost.exe",
            BundlerParameters.FromExistingBundle(args[0], mainFile.RelativePath));
    }
}
```

We can now put breakpoints on `CreateProcessW`, and `WriteProcessMemory` , attach a new instance of x64dbg to `InstallUtil.exe` after it's created. Then we it all our WriteProcessMemory breakpoints and wait for the PE to be populated.

![x64dbg picture](/x64dbg_2.png)
But nothing happens! It turns out that there are multiple mistakes with how process hollowing is implemented, and this challenge is ***completely broken*** if you want to solve it dynamically :/

### Static Approach

After the CTF, I attempted to solve this challenge statically.

```csharp
Stream manifestResourceStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("MySQLdb.Redundant.attrib.obf");
byte[] array = new byte[manifestResourceStream.Length];
manifestResourceStream.Read(array, 0, array.Length);
byte[] array2 = mySQL.dbs(array.ToArray<byte>(), 0xFB);
```

```csharp
public static byte[] dbs(byte[] d, byte hx)
{
	byte[] array = new byte[d.Length];
	for (int i = 0; i < d.Length; i++)
	{
		array[i] = d[i] ^ hx;
	}
	return array;
}
```

We can grab the resource from dnSpy, and decrypt it with a 1 byte XOR using Cyberchef. Unlike all the other Windows executables in this CTF, we actually get a MSVC PE binary! 

After decompiling with IDA, we find nothing interesting in the main function. Armed with the experience from solving `Sneaky`, and the fact that this challenge is from the same author, it's time to search for unused functions. We do indeed find another function in the `.rodata` section. This function seems to assemble a large amount of stack strings, but IDA has helpfully inlined them all for us.
![ida picture](ida_2.png)

Before I actually start trying to crack hashes, let's do a quick sanity check. The challenge description constantly mentions `MySQL`, so let's look up the password hash on [CrackStation](https://crackstation.net/). We get lucky, and there's a hit! `MySQL:D@rkn3$$`

However, when trying to login to the form at https://issessionsctf-secure-login.chals.io/, this doesn't work.

# Conclusion

I hope you enjoyed reading this year's set of RE writeups! There were way more this year :). You can find last year's writeups [over here](https://fastcall.dev/posts/iss-rev-2024/#).
