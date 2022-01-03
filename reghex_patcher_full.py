credits = "RegHex Patcher by Destitute-Streetdwelling-Guttersnipe (Credits to leogx9r & rainbowpigeon for signatures and patching logic)"

import re, sys, struct
import patches as Fixes

def main():
    print(f"[-] ---- {credits}\n")
    input_file = sys.argv[1] if len(sys.argv) > 1 else exit(f"Usage: {sys.argv[0]} input_file output_file")
    output_file = sys.argv[2] if len(sys.argv) > 2 else input_file
    PatchFile(input_file, output_file)

def PatchFile(input_file, output_file):
    with open(input_file, 'rb') as file:
        data = bytearray(file.read())
    SplitFatBinary(data)
    with open(output_file, "wb") as file:
        file.write(data)
    print(f"[+] Patched file saved to {output_file}")

def FindRegHex(reghex, data, onlyFirstMatch = False):
    regex = bytes(re.sub(r"\b([0-9a-fA-F]{2})\b", r"\\x\1", reghex), encoding='utf-8') # escape hex bytes
    it = re.finditer(regex.replace(b' ', b''), data, re.DOTALL) # remove all spaces
    return next(it, None) if onlyFirstMatch else it

def Patch(data, display_offset = 0):
    patches = {}
    refs = {}
    for fix in FindFixes(data):
        PatchFix(fix, data, display_offset, refs, patches)
    for offset in patches:
        data[offset : offset + len(patches[offset])] = patches[offset]
    return data

def PatchFix(fix, data, display_offset, refs, patches):
    arch, address2offset, offset2address = FileInfo(data)
    offset = None
    for match in FindRegHex(fix.reghex, data):
        for groupIndex in range(1, match.lastindex + 1) if match.lastindex else range(1):
            offset0 = offset = match.start(groupIndex)
            address0 = address = ConvertBetweenAddressAndOffset(offset2address, offset)
            if address0 == None: continue
            if fix.ref:
                address = Ref2Address(address0, data[offset-4 : offset+4], arch)
                offset = ConvertBetweenAddressAndOffset(address2offset, address)
                if offset == None: continue
            addr0_info = f"a:0x{address0:x} o:0x{offset0 + display_offset:06x}"
            addr_info = f"a:0x{address:x} o:0x{offset + display_offset:06x}" if address != address0 else " " * len(addr0_info)
            if not fix.look_behind:
                if not refs.get(address0): refs[address0] = fix.name # address0 can be equal to address when ref not exist
                if not refs.get(address): refs[address] = fix.name.split('.')[-1] # keep the part after the dot
                patch = bytes.fromhex(fix.patch[groupIndex-1] if isinstance(fix.patch, list) else fix.patch) # use the whole fix.patch if it's not a list
                if patch != b'': print(f"[+] Patch at {addr0_info} -> {addr_info} {fix.name} {patch.hex(' ')}")
                patches[offset] = patch
            elif refs.get(address) or refs.get(address0):
                if address == address0 or not refs.get(address): addr_info = " " * len(addr0_info)
                ref_info = f"{fix.name} <- {addr0_info} -> {addr_info} {refs.get(address0, '.' + refs.get(address, '?'))}"
                for m in FindRegHex(function_prologue_reghex[arch], data[0 : offset0]):
                    if len(m.group(0)) > 1: offset = m.start() # NOTE: skip too short match to exclude false positive
                address = ConvertBetweenAddressAndOffset(offset2address, offset)
                print(f"[-] Found at a:0x{address:x} o:0x{offset + display_offset:06x} {ref_info}")
    if fix.patch != '' and not offset: print(f"[!] Can not find pattern: {fix.name} {fix.reghex}")

AMD64 = 'amd64' # arch x86-64
ARM64 = 'arm64' # arch AArch64

function_prologue_reghex = {
    AMD64:  r"( [53 55-57] | 41 [54-57] | 48 8B EC | 48 89 E5 )+" ## push r?x ; push r1? ; mov rbp, rsp ; mov rbp, rsp
          + r"(48 [81 83] EC)?", ## sub rsp, ?,
    ARM64:  r"(. 03 1E AA  .{3} [94 97]  FE 03 . AA)?" ## mov x?, x30 ; bl ? ; mov x30, x? 
          + r"( FF . . D1 | [F4 F6 F8 FA FC FD] . . A9 | [E9 EB] . . 6D | FD . . 91 )+", ## sub sp, sp, ? ; stp x?, x?, [sp + ?] ; add x29, sp, ?
}

def Ref2Address(base, byte_array, arch):
    # TODO: use byteorder from FileInfo(data)
    if arch == ARM64: # PC relative instructions of arm64
        if FindRegHex(r"[90 B0 D0 F0] .{3} 91$", byte_array, True): # ADRP & ADD instructions
            (instr, instr2) = struct.unpack("<2L", byte_array) # 2 unsigned long in little-endian
            immlo = (instr & 0x60000000) >> 29
            immhi = (instr & 0xffffe0) >> 3
            value64 = (immlo | immhi) << 12 # PAGE_SIZE = 0x1000 = 4096
            if value64 >> 33: value64 -= 1 << 34 # extend sign from MSB (bit 33)
            imm12 = (instr2 & 0x3ffc00) >> 10
            if instr2 & 0xc00000: imm12 <<= 12
            page_address = base >> 12 << 12 # clear 12 LSB
            return page_address + value64 + imm12
        elif FindRegHex(r"[94 97 14 17]$", byte_array, True): # BL / B instruction
            address = struct.unpack("<L", byte_array[4:])[0] << 2 & ((1 << 28) - 1) # append 2 zero LSB, discard 6 MSB
            if address >> 27: address -= 1 << 28 # extend sign from MSB (bit 27)
            return base + address
    elif arch == AMD64: # RVA & VA instructions of x64
        address = struct.unpack("<l", byte_array[4:])[0] # address size is 4 bytes
        if FindRegHex(r"( ( [48 4C] 8D | 0F 10 ) [05 0D 15 1D 25 2D 35 3D] | [E8 E9] )$", byte_array[:4], True):
            return base + 4 + address # RVA reference is based on next instruction (which OFTEN is at the next 4 bytes)
        if FindRegHex(r"( [B8-BB BD-BF] | 8A [80-84 86-8C 8E-94 96-97] )$", byte_array[:4], True):
            return address # VA reference
    return base

def FindFixes(data):
    detected = set()
    for fix in Fixes.detections:
        for m in FindRegHex(fix.reghex, data):
            detected |= set([ fix.name, *m.groups() ])
            print(f"[-] Detected at 0x{m.start():x}: {fix.name} {m.groups()} in {m.group(0)}")
    for tags, fixes in Fixes.tagged_fixes:
        if set(tags) == detected: return fixes
    exit("[!] Can not find fixes for target file")

def SplitFatBinary(data):
    (magic, num_archs) = struct.unpack(">2L", data[:4*2])
    if magic == 0xCAFEBABE: # MacOS universal binary
        header_size = 4*5
        for i in range(num_archs):
            # with open(f"macho_executable{i}", "wb") as file: file.write(data)
            header_offset = 4*2 + header_size*i
            (cpu_type, cpu_subtype, offset, size, align) = struct.unpack(">5L", data[header_offset:header_offset + header_size])
            print(f"[+] ---- at 0x{offset:x}: Executable for CPU 0x{cpu_type:x} 0x{cpu_subtype:x}")
            data[offset:offset + size] = Patch(data[offset:offset + size], offset)
    else:
        data[:] = Patch(data)

class MemoizeFirstArg: # adapt from https://stackoverflow.com/questions/1988804/what-is-memoization-and-how-can-i-use-it-in-python
    def __init__(self, f):
        self.f = f
        self.first_arg = None
        self.memo = None
    def __call__(self, *args):
        if self.first_arg != args[0]: # memoize when first arg changes
            self.first_arg = args[0]
            self.memo = self.f(*args)
        return self.memo

@MemoizeFirstArg
def FileInfo(data):
    if re.search(b"^MZ", data):
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        arch = { 0x8664: AMD64, 0xAA64: ARM64}[pe.FILE_HEADER.Machine] # die on unknown arch
        sections = [(pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress, s.PointerToRawData) for s in pe.sections]
    elif re.search(b"^\x7FELF", data):
        from elftools.elf.elffile import ELFFile # pip3 install pyelftools
        import io
        elf = ELFFile(io.BytesIO(data))
        arch = { 'EM_X86_64': AMD64, 'EM_AARCH64': ARM64}[elf.header['e_machine']] # die on unknown arch
        sections = [(s.header['sh_addr'], s.header['sh_offset']) for s in elf.iter_sections()]
    elif re.search(b"^\xCF\xFA\xED\xFE", data):
        from macho_parser.macho_parser import MachO # pip3 install git+https://github.com/Destitute-Streetdwelling-Guttersnipe/macho_parser.git
        macho = MachO(mm=data) # macho_parser was patched to use bytearray (instead of reading from file)
        arch = { 0x1000007: AMD64, 0x100000c: ARM64}[macho.get_header().cputype] # die on unknown arch
        sections = [(s.addr, s.offset) for s in macho.get_sections()]
    else:
        exit("[!] Can not detect file type")
    address2offset = sorted([(addr, offset) for addr, offset in sections if addr > 0 and offset > 0], reverse=True) # sort by address
    return arch, address2offset, sorted([(offset, addr) for addr, offset in address2offset], reverse=True) # sort by offset

def ConvertBetweenAddressAndOffset(sorted_pairs, position):
    for first_part, second_part in sorted_pairs:
        if position >= first_part: return position - first_part + second_part
    return None

if __name__ == "__main__":
    main()
