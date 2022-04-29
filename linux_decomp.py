from elftools.elf.elffile import ELFFile
from capstone import *
import sys

prev_mnemonic = ""
mov_addr = ""
key_addr = []
filename = sys.argv[1]


def merge_hex_key(full_hex_key):
    hex_xored = 0
    for chunk in [full_hex_key[i : i + 2] for i in range(0, len(full_hex_key), 2)]:
        hex_xored ^= int(chunk, 16)
    return hex(hex_xored)


try:
    elf = ELFFile(open(filename, "rb"))
except:
    raise Exception("[-] This file is not an ELF file: %s" % filename)

ENTRY_ADDRESS = elf.header.e_entry
DATA = open(filename, "rb").read()

md = Cs(CS_ARCH_X86, CS_MODE_32 + CS_MODE_LITTLE_ENDIAN)
asm = md.disasm(DATA, ENTRY_ADDRESS)

for line in asm:
    if (
        prev_mnemonic == "mov"
        and line.mnemonic == "cmp"
        and prev_valid
        and line.op_str.split(", ")[0].startswith("word ptr")
        and mov_addr.startswith("dword ptr")
    ):
        key_addr.append(mov_addr[mov_addr.find("[") + 1 : mov_addr.find("]")])
    prev_valid = bool(
        len(line.op_str.split(", ")) == 2 and line.op_str.split(", ")[0] == "eax"
    )
    prev_mnemonic = line.mnemonic
    if line.mnemonic == "mov":
        mov_addr = line.op_str.split(", ")[1]


key_addr = list(dict.fromkeys(key_addr))

data_entry_addr = elf.get_section_by_name(".data").header["sh_addr"]
data = elf.get_section_by_name(".data").data()

for key_loc in key_addr:
    offset = int(key_loc, 16) - data_entry_addr
    key = reversed(data[offset:].split(b"\x00", 1)[0])
    key_plaintext = "".join(format(int(x), "x") for x in key).upper()
    key_merged = merge_hex_key(key_plaintext)
    print(
        f"Found potential Mirai XOR key at location {key_loc}\t->\t{key_plaintext}\t->\t{key_merged}"
    )
