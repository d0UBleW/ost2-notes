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

## System Mechanisms

### Interrupt Descriptor Table (IDT)

- contains handlers for different interrupts
- although it is named `interrupt`, it also tracks synchronous exception traps but not `syscall` exceptions
- `SIDT` assembly instruction could be executed from userland (unprivileged instruction) to get the address of `IDT` and with arbitrary read primitive, we could leak kernel addresses
- `SIDT` store table address into the destination operand
- `LIDT` is privileged instruction, **l**oad values in the source operand into the table

### Global Descriptor Table (GDT)

- table of memory regions
- `gs` register (64-bit), `fs` (32-bit)
  - self note: usually use to access `TEB` (thread environment block) and `PEB` (process environment block)
- accessed with `SGDT` and `LGDT` assembly instructions

### System Service Descriptor Table (SSDT)

- equivalent of Linux syscall table
- `nt!KiServiceTable` is referenced by `KeServiceDescriptorTable`
- To calculate the corresponding syscall routine (useful for analyzing new syscall)
  1. `dd nt!KiServiceTable + <syscall number>*4` to get the relative offset
  2. `u KiServiceTable + (<offset> >>> 4)` to disassemble the routine
- <https://github.com/j00ru/windows-syscalls>

### Alertable State

- use by `win32k.sys` for userland callback
- asynchronous procedure call (APC)
- the procedure is run as soon as an alertable thread is scheduled
- functions that could set alertable thread:
  - `KeWaitForSingleObject()`
  - `KeWaitForMultipleObjects()`
  - with the argument `Alertable` set to `TRUE`
- useful for pivoting to userland after getting kernel code execution

```cpp
NTSTATUS
KeWaitForSingleObject (
    PVOID Object,
    KWAIT_REASON WaitReason,
    KPROCESSOR_MODE WaitMode,
    BOOLEAN Alertable, // <=====
    PLARGE_INTEGER Timeout
    );

NTSTATUS
KeWaitForMultipleObjects (
    ULONG Count,
    PVOID Object[],
    WaitType,
    KWAIT_REASON WaitReason,
    KPROCESSOR_MODE WaitMode,
    BOOLEAN Alertable, // <=====
    PLARGE_INTEGER Timeout,
    PKWAIT_BLOCK WaitBlockArray
    );
```

### Interrupt Request Level (IRQL)

- used by kernel to check if the caller that triggered the interrupt has appropriate level or not
- if not appropriate, it causes BSOD (blue screen of death)
- level 0 (`PASSIVE_LEVEL` or `LOW_LEVEL` in WinDbg) is for user thread
- code running on higher IRQL cannot be interrupted by lower IRQL code
  - `APC_LEVEL` (level 1): APCs are disabled and cannot interrupt the thread, e.g., `KeEnterCriticalRegion()`, and `KeLeaveCriticalRegion()`
  - `DISPATCH_LEVEL` (level 2): both dispatch and APC are disabled
- when doing kernel exploitation and we try to access userland data, this would usually issue a page fault to map the memory
- page fault is allowed at IRQL <= 1, however at `DISPATCH_LEVEL` this would cause BSOD
- IRQL information is stored in `CR8` register

### Object Manager

- serve as an API to create, modify, deletes objects
- Direct Kernel Object Manipulation (DKOM) used by rootkit to bypass AV, which tracks the usage of object manager API

### `_E*` structures vs. `_K*` structures

- `_E*` is executive version
- `_K*` is kernel version
- `_K*` structure is usually the first member of `_E*` structure

### Common Objects

- `_EPROCESS`
- `_ETHREAD`
- `_EJOB`
- `_SECTION_OBJECT_POINTERS`
- `_FILE_OBJECT`
- `_KTOKEN`: for privilege escalation, patch our `_EPROCESS` structure to point to system level `_TOKEN`
- `_KSEMAPHORE`: for synchronization
- `_KMUTANT`: for mutex
- `_KTIMER`
- `_CM_KEY_BODY`

### Synchronization

- mutual exclusion principle
- prevent UAF and race condition

#### Interlocked Operation

- `_interlockedbittestandset64(&OwnerThread->ThreadLock, 0i64)`
- `lock bts [rbx+_KTHREAD.ThreadLock]`
- tests if 0th bit is set, and set it to 1

#### Spinlock

- while loop to constantly check if the resource is locked or not

#### Mutex

- `KeWaitForSingleObject()`: API to wait for mutex
- If our thread cannot obtain the mutex, our thread would go into blocking state and might become alertable

#### Critical Section

- adjust IRQL to prevent interrupts
- cannot be shared across processes unlike mutex
