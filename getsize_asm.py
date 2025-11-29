from capstone import *

# Inițializează disassembler-ul pentru x86_64 (arhitectură pe 64 de biți)
md = Cs(CS_ARCH_X86, CS_MODE_64)

# Codul binar pentru instrucțiunile specificate
code = b"\x48\x31\xc0" \
       b"\x50" \
       b"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00" \
       b"\x50" \
       b"\x48\x89\xe7" \
       b"\x48\xc7\xc0\x3b\x00\x00\x00" \
       b"\x48\x31\xf6" \
       b"\x48\x31\xd2" \
       b"\x0f\x05"

# Disassemblează instrucțiunile și calculează dimensiunea totală
total_size = 0
for instruction in md.disasm(code, 0x1000):
    print(f"{instruction.mnemonic} {instruction.op_str} -> {instruction.size} bytes")
    total_size += instruction.size

print(f"\nDimensiunea totală a instrucțiunilor: {total_size} bytes")
