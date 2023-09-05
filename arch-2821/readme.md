# Windows Kernel Internals

## Generalities

### Windows APIs

- Windows API
  - callable from user mode
  - wrapper to call Native API, e.g., `CreateFile`, with extra sane checks
- Native API
  - callable from user mode
  - wrapper to syscall, context switch to kernel mode and call Kernel API, e.g., `NtCreateFile`
- Kernel API - e.g., `ZwCreateFile`

`CreateFile` -> `NtCreateFile` -> `ZwCreateFile`

### Processes

- A process has:
  - VA space
  - handles to system objects
  - an access token
  - PID
  - one thread
- Tracked in kernel with [`_EPROCESS`](https://www.vergiliusproject.com/kernels/x64/Windows%2011/21H2%20(RTM)/_EPROCESS) structure

### Threads

- Two stacks, user and kernel mode
- Thread-Local Storage (TLS): private user mode storage
  - self note: in Linux, it stores stack cookie value
- Tracked in kernel with [`_ETHREAD`](https://www.vergiliusproject.com/kernels/x64/Windows%2011/21H2%20(RTM)/_ETHREAD) structure

### Virtual Memory

- 32-bit arch:
  - half (2GB) is for user space, another half (2GB) is for kernel space
- 64-bit arch
  - user
    - address starts with `0x0000`, range: `0x00000000 00000000` - `0x00007FFF FFFFFFFF`
  - kernel
    - address starts with `0xFFFF`, range: `0xFFFF8000 00000000` - `0xFFFFFFFF FFFFFFFF`
- memory page
  - 4KB or 1MB
  - permissions are set per page
    - self note: if some part of `.data` section shares the same memory page with `.text` section, this data could be used for `ROP` (source: Gynvael)

### Virtual Address Spaces

- kernel page tables used to be accessible by userland page tables
  - Meltdown and Spectre side-channel attack
- `KPTI` (Kernel Page Table Isolation)
  - make kernel page tables inaccessible
  - self note:
    - experience in Linux, could be bypassed with `KPTI` trampoline to safely return from kernel space to userspace, otherwise it causes segfault
    - another trick is to use signal handler since the segfault happens after returning to userspace <https://trungnguyen1909.github.io/blog/post/matesctf/KSMASH/>

### Sessions

- Session 0 for system services
- Session 1 and above for interactive login sessions

### Hypervisor vs. Kernel vs. User

- Hypervisor Mode: Ring -1
- Kernel Mode: Ring 0
  - has R/W access to userland (what about `SMAP`?)
  - Limited userland code execution due to `SMEP`
    - solution is to do `ROP` (reusing kernel space code) but need to defeat `KASLR`
  - self note: `SMAP` and `SMEP` are set on `CR4` register, used to be overwritable based on past blogposts that I read on Linux kernel exploitation
- User Mode: Ring 3

### Objects

- consists of data, attributes, and functions
- example: `_EPROCESS`, `_ETHREAD`, `_FILE_OBJECT`
- `ObCreateObject()`
- Sysinternal tools: `WinObj`

### Handles

- similar to file descriptor in Linux
- references to an instance of an object
- an object could be referred by multiple handles
- has its own permissions
- each process has its own handle table
- generally created with `ObOpenObjectByName()`, `ObOpenObjectByPointer()`

## System Components

- Any `_E*` structure would typically have the kernel counterpart `_K*` structure
- Every windows system has these processes which may be useful to get system level token
  - smss.exe
  - lsm.exe
  - csrss.exe
  - wininit.exe
  - winlogon.exe
  - services.exe
  - lsass.exe
  - svchost.exe

### NTDLL.DLL

- libc equivalent
- abstracting access to syscall
- most functions that we call comes from `kernel32.dll` and `user32.dll`, which then calls `ntdll.dll`
- manage heap
- contains CRT (C runtime) functions, e.g., `memcpy()`
- the wrapper might have some sanity checks which may not be ideal to reach kernel space; hence, need to invoke syscall on our own with raw assembly instruction

### I/O processing

- User mode (Ring 3)
  1. user code calls `kernel32.dll!ReadFile()`
  2. `kernel32.dll` calls `ntdll.dll!NtReadFile()`
  3. `ntdll` invoke syscall, context switch to kernel mode
- Kernel mode (Ring 0)
  1. `ntoskrnl.exe` calls `NtReadFile()`
  2. `ntoskrnl.exe` invoke driver
  3. `driver.sys` handles I/O operation

### Executive Layer

Manage:

- processes
- threads
- system configuration
- general I/O

### Kernel Layer

- abstracting the hardware layer

### Hardware Abstraction Layer (HAL)

- well documented
- commonly used for windows kernel exploitation
- contains many interesting pointers to functions or structures
- does not have address randomization until recently (how recent?)

### Win32k.sys

- for windowing stuff and browser
- handles syscalls from `gdi32.dll` and `user32.dll`
- used to be the most popular attack surface before sandbox protection was implemented (syscall filter, similar to `seccomp`)
- sometimes leads to UAF due to callback into `user32.dll` inside kernel mode
