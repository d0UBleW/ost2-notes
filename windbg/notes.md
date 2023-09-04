# Notes

## WinDbg

| WinDbg    | GDB    | Description    |
|---------- | --------------- | --------------- |
| .restart     | r    | restart    |
| g     | c    | continue    |
| .reload /f     |     | reload symbol    |
| u, uf     | disass, x/i    | disassemble    |
| bp     | break    | breakpoint    |
| bu     |     | breakpoint on undefined symbol    |
| bl     | info break    | list breakpoint    |
| bc     | del break    | delete/clear breakpoint    |
| bd     | dis break    | disable breakpoint    |
| be     | en break    | enable breakpoint    |
| bp /1     | tbreak    | temporary breakpoint    |
| ba w \<size> \<addr>     |     | break on write access    |
| ba r \<size> \<addr>     |     | break on read and write access    |
| ba e \<size> \<addr>     |     | break on execute    |
| r \<r1>, \<r2>     | info reg r1 r2    | view register    |
| db \<addr> L\<n>     | x/nbx    | dump memory (byte)    |
| dd \<addr> L\<n>     | x/nwx    | dump memory (dword)    |
| dq \<addr> L\<n>     | x/ngx    | dump memory (qword)    |
| da \<addr>     | x/s    | dump memory (qword)    |
| dv     | info locals    | display local variables    |
| dt     | ptypes    | display structure    |
| dt \<struct> \<addr>     | | display mem addr as struct    |
| t     | si    | step into (trace)    |
| p     | ni    | step over    |
| pt, gu     | fin    | until return    |
| k     | bt    | backtrace    |
| sxe     |    | set exception enable    |
| sxi     |    | set exception ignore    |
| sxe ld    |    | set exception on module load    |
| lm    |    | list loaded modules    |
| !load    |    | load 3rd party plugin    |
| !unload    |    | unload 3rd party plugin    |
| rdmsr    |    | read model specific registers (MSRs)    |
| wrmsr    |    | write model specific registers (MSRs)    |
| !process    |    | examine process context    |
| .process    |    | switch process context    |
| !ms_gdt    |    | examine global descriptor table (`SwishDbg`)    |
| !idt, !ms_idt    |    | examine interrupt descriptor table    |
| !pte    |    | examine page table entries    |
| !vtop    |    | translate **v**irtual **to** **p**hysical address    |
| !ptov    |    | list all **p**hysical **to** **v**irtual address mapping of a process |
| !pool    |    | associate memory address with a data structure or driver |
| !irql    |    | examine windows interrupt request level |


- `u $exentry`
- `sxe -c ".lastevent" ld`: run `.lastevent` on exception and break
- `sxe -c ".lastevent; g" ld` or `sxi -c ".lastevent" ld`: run `.lastevent` on exception and continue
- `sxi -c "" ld`: remove exception command handler
- `lm sm`: sort alphabetically
- `lm u`: userspace
- `lm k`: kernel space
- `lm f`: show filesystem path
- `lm v`: verbose output
- `lm a <addr>`: show which module the address space belongs to
- `lm ukfsm`: show filesystem path
- `!process -1 0`: display current process context
- `!process 0 0`: list all processes
- `!process 0 0 <exe>`: search process with executable name
- `!process <pid> 0`: display process with specified `pid`
- `.process /i /r /p <addr>`: switch process context with `PROCESS` address from `!process` output
