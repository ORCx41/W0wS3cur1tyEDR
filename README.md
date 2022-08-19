### W0wS3cur1tyEDR : Project for people who want to know more about edr's

### what does it do:
- W0wS3cur1tyEDR consists from 2 projects : 
    - [W0wS3cur1ty](https://github.com/ORCx41/W0wS3cur1tyEDR/tree/main/W0wS3cur1ty), which is the dll file that will get injected to a target process
    - [WSEdr](https://github.com/ORCx41/W0wS3cur1tyEDR/tree/main/WSEdr), the enjector that will inject `W0wS3cur1ty.dll` into the target process
- the dll files, create a new console, and write data to it, it hooks (using minhook library):
    - NtCreateThreadEx
    - NtWriteVirtualMemory
    - NtAllocateVirtualMemory
    - NtProtectVirtualMemory 
- some hooks can even dump the RWX sections     
- i added a 'payload.dll' file that can be used as a test, it runs all the 4 hooked api's and can be injected automatically by the juicy edr, it runs `metasploit's calc shellcode` so it may be detected by your av before the demo, so dw im not hacking you.

### USAGE:
```
[i] USAGE : WSEdr.exe <process name to monitor> <*options>
                1. Inject 'W0wS3cur1ty.dll' [The Edr Like Dll] to The Target Process
                2. Inject 'Payload.dll' [Dll File That Runs Metasploit's x64 Calc] to The Target Process
```


### Demo `Monitoring`:
![img](https://github.com/ORCx41/W0wS3cur1tyEDR/blob/main/images/demo.png?raw=true)

### Demo `before`:
![img](https://github.com/ORCx41/W0wS3cur1tyEDR/blob/main/images/before.png?raw=true)

### Demo `after`:
![img](https://github.com/ORCx41/W0wS3cur1tyEDR/blob/main/images/after.png?raw=true)

### Note: Do not use this project as a 'Stable' code, it may crash / do unstable shit ...



