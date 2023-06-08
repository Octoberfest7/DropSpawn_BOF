# DropSpawn

## Introduction
DropSpawn is a CobaltStrike BOF used to spawn additional Beacons via a relatively unknown method of DLL hijacking. Works x86-x86, x64-x64, and x86-x64/vice versa. Use as an alternative to process injection.  

[Windows executables will follow the DLL search order](https://dmcxblue.gitbook.io/red-team-notes/persistence/dll-search-order-hijacking) when trying to load DLL's whose absolute paths were not specified:  
![image](https://github.com/Octoberfest7/DropSpawn_BOF/assets/91164728/c4251d34-f7ba-45bc-84b4-27536c757324)

DLL hijacking typically requires that either:  

***A.*** A user has write permissions in a folder with a higher search order precedence than where the real DLL resides  

or  

***B.*** That the DLL in question doesn't exist anywhere on the system, in which case it can be placed in a user-writable folder in the user's %PATH% variable (like %USERPROFILE%\appdata\local\microsoft\windowsapps).

These requirements rule out DLL hijacking for executables residing in C:\Windows\System32 because almost all DLL's that these executables load also reside in System32. Copying a System32 executable to a user-writable location and executing it there is an option, but isn't very OPSEC safe because System32 binaries running from alternate locations are easy to identify.

***DropSpawn enables DLL hijacking using System32 executables (and others found in additional non-user-writable folders) by spoofing the "The directory from which the application is loaded" to an arbitrary user-specified one.***

### Note:  
The public release of DropSpawn differs slightly from the non-public one. The non-public release leverages a proprietary payload generator, making the experience much more seamless for the operator. The public release has been altered slightly to account for the fact that users will have their own ways of generating  DLL hijack compatible payloads. A Python3 script as well as source code for a demonstration DLL have been included to assist users in integrating and weaponizing dropspawn. 

## How to Use
### 1.
Identify some target executables that try to load DLL's without specifying their absolute paths. You can do this by copying the exe into a user-writable directory and executing it while monitoring it with [Procmon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon). In this example we'll use WerFault.exe which normally resides at C:\Windows\System32\WerFault.exe
![image](https://github.com/Octoberfest7/DropSpawn_BOF/assets/91164728/e4c88036-0018-41d4-88a1-cd429669e39b)

In the above example cryptsp.dll, wer.dll, dbghelp.dll, and bcrypt.dll are all viable candidates because their absolute paths were not specified within WerFault; as a result, WerFault will attempt to load them from its application directory first before resorting to the rest of the DLL search order. Note that this typically isn't a concern because WerFault's application directory IS System32.

### 2.
Download one of the hijackable DLL's from the target system.   

![image](https://github.com/Octoberfest7/DropSpawn_BOF/assets/91164728/2938bd57-90ff-450f-b82a-0704292f30f7)
This is necessary so that we can extract its exports and include them in our payload DLL. It is important to grab the hijackable DLL from the same machine you wish you use DropSpawn on, as DLL's change between Windows versions. Additionally, if you are running a x86 beacon and want to spawn an x64 beacon using DropSpawn, make sure you download the x64 version of the real DLL by specifying 'C:\windows\sysnative\...' instead of 'C:\windows\system32\...'.

### 3.
Run generate_dll.py, passing in the downloaded DLL and the desired payload architecture. Generate_dll.py is a modified version of [this script](https://github.com/tothi/dll-hijack-by-proxying). It will parse the supplied DLL, create a .def file containing the DLL's exports, and call MingW to compile our demonstration payload DLL. When the spawned process tries to call a real function within the spoofed DLL, our payload DLL will forward the call to the real DLL located in System32 so that the host process doesn't crash.
![image](https://github.com/Octoberfest7/DropSpawn_BOF/assets/91164728/eb9f10d9-4775-4ea1-8de5-ff6a8ec5ded6)

### 4.
Call dropspawn using the generated payload DLL. 

***dropspawn \<payload DLL\> \<x86|x64\> \<program to spawn\> \[writable target folder\] \[parent\]***
  
**payload DLL** - the full path to the generated DLL payload.  
**architecture** - the architecture of the process you wish to spawn  
**program to spawn** - the name/path of the process you wish to spawn. If this process resides in System32(or syswow64), you can just specify the name. Otherwise, specify the full path. You can also supply arguments command line arguments to the process. If there are spaces in the path/if you use arguments, wrap the whole thing in quotes.  
**writable target folder** - Optional. If left blank, dropspawn will try to use the Beacon's current directory. Use quotes if there are spaces in the path.  
**parent** - Optional. The name of the process to use for PPID spoofing with the newly spawned process. If a process is specified that has multiple running instances of difference privilege levels (i.e. svchost.exe), dropspawn will try and identify one that can be used for PPID spoofing.

Example: dropspawn /root/gitlab/DropSpawn_BOF/dist/dbgcore.dll x64 "WerFault.exe -u -p 4352 -s 160" C:\users\user\appdata\local\temp explorer.exe

This will drop the payload DLL 'dbgcore.dll' to disk at 'c:\users\user\appdata\local\temp\dbgcore.dll' and spawn a x64 WerFault.exe process with the commandline arguments '-u -p 4352 -s 160' and explorer.exe as the parent process.

![image](https://github.com/Octoberfest7/DropSpawn_BOF/assets/91164728/1d1da108-9603-4bd0-8cff-4f47960a5b8c)

![image](https://github.com/Octoberfest7/DropSpawn_BOF/assets/91164728/730bfe59-9808-413c-8e70-9e8f3788f856)

### 5.  
Cleanup is easy. By including the [Self-Deletion](https://github.com/LloydLabs/delete-self-poc) function in the payload DLL that is dropped to disk, it will be deleted as soon as our new process spawns and loads it. This is a game changer, as typically the DLL would be locked on disk so long as our process that loaded it continues to run. If the Self-Deletion technique fails for some reason (or the process fails to spawn), DropSpawn will attempt to delete the payload DLL from disk and will inform the user of the result of the operation either way.

## Detection
Process injection typically follows the open remote process -> allocate remote memory -> write remote memory -> execute remote memory chain, with an option to spawn a new process at the beginning instead of using an existing one. DropSpawn only creates a new process; the newly spawned process is responsible for allocating, writing, and executing shellcode, so we can avoid a lot of the IOC's typically associated with remote process injection.  

This technique is of course at the mercy of how good your DLL payloads are. But we can take a look at what Windows sees (this next section using the private version of DropSpawn and spawning Beacons).

As far as Event Viewer is concerned, everything looks normal:
![image](https://github.com/Octoberfest7/DropSpawn_BOF/assets/91164728/bf68fd99-b673-470a-8d51-b379ceca4769)

In MDE there is very little to see.  

Running dropspawn: 

![image](https://github.com/Octoberfest7/DropSpawn_BOF/assets/91164728/4baa07ff-def4-4aff-a4e9-5b756e3ba6c3)

MDE Logs:

With PPID spoofing:  
![image](https://github.com/Octoberfest7/DropSpawn_BOF/assets/91164728/d10f3ceb-4a75-4826-9b22-8fbf0f53a11b)

Without PPID spoofing:
![image](https://github.com/Octoberfest7/DropSpawn_BOF/assets/91164728/32b8cd5d-d967-466d-b105-eea04c304b8c)

In both cases we see our original beacon process (also a werfault) drop dbgcore.dll to disk, create a new WerFault.exe process, the newly spawned process loading dbgcore.dll, and then renaming (deleting) it. Critically there is no extra scrutiny of dbgcore.dll that often comes with DLL hijacks because we aren't writing it to any often hijacked location, and WerFault.exe (or whatever process you choose to use) isn't really associated with DLL hijacks in the way that things like WmiPrvSE.exe are.

Interestingly it is almost more visible to do this with PPID spoofing than without. This may vary depending on the security product however.

## Limitations
As mentioned, it is essential that users download the real DLL's from the target machine they plan to use DropSpawn on. Using the wrong version of a DLL can result in the spawned process crashing if it tries to call a function that doesn't exist. 

DropSpawn can be used with executables outside System32; be warned however that issues can arise if the process tries to load additional DLL's from the processes true application directory. Because we have spoofed the application directory elswhere, if the real application directory isn't also reachable via the DLL search order otherwise, the process will crash/fail to start because it cannot locate essential DLL's. Always test potential hijacks on development machines before using them in production!

## Credits  
This research first came about as I was exploring how processes assemble their final DLL search order (as it must be determined at runtime due to executables residing in different directories, the current directory being part of the search path, etc).  My research led me to [this](http://www.rohitab.com/discuss/topic/41379-running-native-applications-with-rtlcreateuserprocess/) forum post, which served as the origin of the two critical undocumented API's that are central to this technique. 

They are linked earlier already, but [this post concerning avoiding loader lock](https://www.netspi.com/blog/technical/adversary-simulation/adaptive-dll-hijacking/), [this script for generating a .def file for DLL proxying](https://github.com/tothi/dll-hijack-by-proxying), and [this research on enabling self-deletion of running executables](https://github.com/LloydLabs/delete-self-poc) are essential to producing effective, weaponized DLL payloads suitable for DropSpawn.

When I first published this technique on [Twitter](https://twitter.com/Octoberfest73/status/1642165975805050881?s=20), several others joined the conversation and produced POC's. [SecurityAndStuff produced this one](https://github.com/SecurityAndStuff/DllLoadPath), while [Snovvcrash has his here](https://gist.github.com/snovvcrash/3d5008d7e46d1cc60f0f8bdc8cdb66a5)
