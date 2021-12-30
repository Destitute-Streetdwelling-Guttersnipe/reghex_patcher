credits = "RegHex Patcher by Destitute-Streetdwelling-Guttersnipe (Credits to leogx9r & rainbowpigeon for signatures and patching logic)"

import re, sys
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
    sections, arch = FileInfo(data)
    for fix in FindFixes(data):
        PatchFix(fix, data, display_offset, sections, arch, refs, patches)
    for offset in patches:
        data[offset : offset + len(patches[offset])] = patches[offset]
    return data

def PatchFix(fix, data, display_offset, sections, arch, refs, patches):
    for match in FindRegHex(fix.reghex, data):
        for groupIndex in range(1, match.lastindex + 1) if match.lastindex else range(1):
            offset0 = offset = match.start(groupIndex)
            address0 = address = Offset2Address(sections, offset)
            if fix.ref:
                address = Ref2Address(address, data, offset, arch)
                offset = Address2Offset(sections, address)
            if not fix.look_behind:
                refs[address] = fix.name.split('.')[-1] # keep the part after the dot
                refs[address0] = fix.name # address0 can be equal to address when ref not exist
                patch = bytes.fromhex(fix.patch[groupIndex-1] if groupIndex > 0 and len(fix.patch) >= groupIndex else fix.patch)
                ref_info = f"{refs[address]:20} <- a={hex(address0)} {hex(offset0 + display_offset)}: " if address != address0 else ""
                print(f"[+] Patch at a={hex(address)} {hex(offset + display_offset)}: {ref_info}{fix.name} {patch.hex(' ')}")
                patches[offset] = patch
            elif refs.get(address):
                ref_info = f"{fix.name} <- a={hex(address0)} {hex(offset0 + display_offset)}: {refs.get(address0, '.' + refs.get(address, '?'))}"
                for m in FindRegHex(function_prologue_reghex[arch], data[0 : offset0]):
                    if len(m.group(0)) > 1: offset = m.start() # NOTE: skip too short match to exclude false positive
                address = Offset2Address(sections, offset)
                print(f"[+] Found at a={hex(address)} {hex(offset + display_offset)}: {ref_info}")
        if not fix.ref and not offset: print(f"[!] Can not find pattern: {fix.name} {fix.reghex}")

AMD64 = 'amd64' # arch x86-64
ARM64 = 'arm64' # arch AArch64

function_prologue_reghex = {
    AMD64:  r"( [53 55-57] | 41 [54-57] | 48 8B EC | 48 89 E5 )+" ## push r?x ; push r1? ; mov rbp, rsp ; mov rbp, rsp
          + r"(48 [81 83] EC)?", ## sub rsp, ?,
    ARM64:  r"(. 03 1E AA  .{3} [94 97]  FE 03 . AA)?" ## mov x?, x30 ; bl ? ; mov x30, x? 
          + r"( FF . . D1 | [F4 F6 F8 FA FC FD] . . A9 | [E9 EB] . . 6D | FD . . 91 )+", ## sub sp, sp, ? ; stp x?, x?, [sp + ?] ; add x29, sp, ?
}

def Ref2Address(base, data, offset, arch):
    # TODO: use byteorder from FileInfo(data)
    byte_array = data[offset : offset+4]
    byte_array2 = data[offset-4 : offset]
    if arch == ARM64: # PC relative instructions of arm64
        if FindRegHex(r"[90 B0 D0 F0]$", byte_array2, True) and FindRegHex(r"91$", byte_array, True): # ADRP & ADD instructions
            instr = int.from_bytes(byte_array2, byteorder='little', signed=False)
            immlo = (instr & 0x60000000) >> 29
            immhi = (instr & 0xffffe0) >> 3
            value64 = (immlo | immhi) << 12 # PAGE_SIZE = 0x1000 = 4096
            if value64 >> 33: value64 -= 1 << 34 # extend sign from MSB (bit 33)
            instr2 = int.from_bytes(byte_array, byteorder='little', signed=False)
            imm12 = (instr2 & 0x3ffc00) >> 10
            if instr2 & 0xc00000: imm12 <<= 12
            page_address = base >> 12 << 12 # clear 12 LSB
            return page_address + value64 + imm12
        elif FindRegHex(r"[94 97 14 17]$", byte_array, True): # BL / B instruction
            address = int.from_bytes(byte_array, byteorder='little', signed=False) << 2 & ((1 << 28) - 1) # append 2 zero LSB, discard 6 MSB
            if address >> 27: address -= 1 << 28 # extend sign from MSB (bit 27)
            return base + address
    elif arch == AMD64: # RVA & VA instructions of x64
        address = int.from_bytes(byte_array, byteorder='little', signed=True) # address size is 4 bytes
        if FindRegHex(r"( ( [48 4C] 8D | 0F 10 ) [05 0D 15 1D 25 2D 35 3D] | . . [E8 E9] )$", byte_array2, True):
            return base + 4 + address # RVA reference is based on next instruction (which OFTEN is at the next 4 bytes)
        if FindRegHex(r"( . [B8-BB BD-BF] | 8A [80-84 86-8C 8E-94 96-97] )$", byte_array2, True):
            return address # VA reference
    return base

def FindFixes(data):
    detected = set()
    for fix in Fixes.detections:
        for m in FindRegHex(fix.reghex, data):
            detected |= set([ fix.name, *m.groups() ])
            print("[-] Found at {}: pattern {} {}".format(hex(m.start()), fix.name, m.group(0)))
    print(f"[+] Detected tags: {detected}\n")
    for tags, fixes in Fixes.tagged_fixes:
        if set(tags) == detected: return fixes
    exit("[!] Can not find fixes for target file")

def SplitFatBinary(data):
    import struct
    (magic, num_archs) = struct.unpack(">2L", data[:4*2])
    if magic == 0xCAFEBABE: # MacOS universal binary
        header_size = 4*5
        for i in range(num_archs):
            header_offset = 4*2 + header_size*i
            (cpu_type, cpu_subtype, offset, size, align) = struct.unpack(">5L", data[header_offset:header_offset + header_size])
            print(f"[+] ---- at 0x{offset:x}: Executable for CPU 0x{cpu_type:x} 0x{cpu_subtype:x}")
            data[offset:offset + size] = Patch(data[offset:offset + size], offset)
    else:
        data = Patch(data)

def FileInfo(data):
    sections = []
    if re.search(b"^MZ", data):
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        base = pe.OPTIONAL_HEADER.ImageBase
        arch = { 0x8664: AMD64, 0xAA64: ARM64}[pe.FILE_HEADER.Machine] # die on unknown arch
        sections = [(base + s.VirtualAddress, s.PointerToRawData) for s in pe.sections]
    elif re.search(b"^\x7FELF", data):
        from elftools.elf.elffile import ELFFile # pip3 install pyelftools
        import io
        elf = ELFFile(io.BytesIO(data))
        arch = { 'EM_X86_64': AMD64, 'EM_AARCH64': ARM64}[elf.header['e_machine']] # die on unknown arch
        sections = [(s.header['sh_addr'], s.header['sh_offset']) for s in elf.iter_sections()]
    elif re.search(b"^\xCF\xFA\xED\xFE", data):
        # with open("macho_executable", "wb") as file: file.write(data)
        from macho_parser.macho_parser import MachO # pip3 install git+https://github.com/Destitute-Streetdwelling-Guttersnipe/macho_parser.git
        macho = MachO(mm=data) # macho_parser was patched to use bytearray (instead of reading from file)
        arch = { 0x1000007: AMD64, 0x100000c: ARM64}[macho.get_header().cputype] # die on unknown arch
        sections = [(s.addr, s.offset) for s in macho.get_sections()]
        # print([f"{s.segname} a:{s.vmaddr:x} o:{s.fileoff:x}" for s in macho.get_segments()])
    else:
        print("[!] Can not read file sections")
    sections = [(s[0], s[1]) for s in sections if s[0] > 0 and s[1] > 0]
    # print("[-] sections(address,offset): " + " ".join([f"(0x{s[0]:x},0x{s[1]:x})" for s in sections]))
    return sections, arch

def Address2Offset(sections, address):
    for s_address, s_offset in sorted(sections, key=lambda pair: pair[0], reverse=True): # sorted by address
        if address >= s_address:
            return address - s_address + s_offset
    # print(f"[!] Address 0x{address:x} not found in sections")
    return address

def Offset2Address(sections, offset):
    for s_address, s_offset in sorted(sections, key=lambda pair: pair[1], reverse=True): # sorted by offset
        if offset >= s_offset:
            return offset - s_offset + s_address
    # print(f"[!] Offset 0x{offset:x} not found in sections")
    return offset

if __name__ == "__main__":
    main()
