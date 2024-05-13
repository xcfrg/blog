---
author: "fastcall"
title: "SDCTF 2024 food-without-salt game rev challenge writeup"
date: "2024-05-12"
description: "top tier trolling inside"
summary: "A writup for the Godot game reverse engineering challenge in SDCTF 2024."
tags: ["re", "ctf", "game"]
categories: ["writeups"]
ShowToc: true
draft: false
---

## Initial Look
The challenge gives us a single PE file, `food-without-salt.exe`. Running the challenge reveals that it is a game made using the [Godot engine](https://godotengine.org/), which is free and [open source](https://github.com/godotengine/godot).
![the game](/sdctf-game.png)

I had never reverse engineered a Godot game before, and so I googled for decompilers and found [gdsdecomp](https://github.com/bruvzg/gdsdecomp) relatively quickly. The tool is capable of not only decompilation but full project recovery of a Godot game, perfect!

Loading the binary into gdsdecomp, we run into the first surprise, it's encrypted!
![encrypted!](/sdctf-itsencrypted.png)

Googling around some more, I discovered [this forum thread](https://godot.community/topic/35/protecting-your-godot-project-from-decompilation/) outlining how the encryption works from a developer's perspective. It links to [gdke](https://github.com/char-ptr/gdke), a tool that can easily extract the encryption key from most Godot games.

I tried to use gdke to extract the encryption key from the game, however the extracted encryption key did not work, and was a byte too short to be a valid encryption key. 

![image of gdke](/sdctf-gdke-1.png)

I got stumped here and assumed that this was because the challenge was modified to decrypt the game in a different way. This lead to a multiple hour long wild goose chase in IDA of trying to reverse engineer modifications to a function that was never changed. 
![screenshot of ida pro](/sdctf-ida.png)
After getting this far on Friday, I took a break from SDCTF as [TBTL CTF 2024](https://tbtl.ctfd.io/), was going on simultaneously, and my teammates seemed more interested in playing it instead.

The actual solution to this problem I ended up finding was *a lot funnier*...

## Cheating?

I returned on Sunday with a refreshed mind but no new plan. After a lot more confusion and head-scratching, I noticed that gdke had a new release out, and the update fixed the issue with key extraction!
![screenshot of gdke](/sdctf-gdke-2.png)
*The key is now padded correctly with the extra zero*

Was this just some huge coincidence? Some dumb luck? Of course not.

Someone playing the CTF has reported the issue as [a bug](https://github.com/char-ptr/gdke/issues/12) to the maintainer, and he had fixed and pushed a new release during the CTF, of course without the knowledge that it was an **active ctf challenge.**
![screenshot of github](/sdctf-github.png)

The person who reported the bug attempted to hide the fact that this was the ctf challenge binary by renaming it. But due to the very poor redaction you can easily spot the encryption key for the challenge in the screenshot.

## Solution

After obtaining the encryption key, we can enter it into gdsdecomp to extract and recover the entire Godot project in it's entirety.
![screenshot of gdsdecomp](/sdctf-setting-key.png)
![screenshot of gdsdecomp extraction](/sdctf-extracting.png)
After extraction, we open up the project with the correct version of Godot Editor, which you can find in the metadata of the binary, or by just looking in the gdsdecomp logs, which will tell you what version of Godot was used.
![screenshot of windows properties](/sdctf-metadata.png)
After opening the project up in the editor and searching around a bit, we find the flag in the tilemap, off screen from the game.

![screenshot of godot editor with the flag](/sdctf-flag.png)

`SDCTF{Welc0m3_Back_Brack3ys}`
