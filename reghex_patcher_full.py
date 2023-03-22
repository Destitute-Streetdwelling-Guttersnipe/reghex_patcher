credits = "RegHex Patcher by Destitute-Streetdwelling-Guttersnipe (Thanks to leogx9r & rainbowpigeon for inspiration)"
import re, sys, struct, io, patches as Fixes

def main():
    print(f"[-] ---- {credits}\nUsage: {sys.argv[0]} input_file [output_file]")
    input_file = sys.argv[1] if len(sys.argv) > 1 else exit()
    with open(input_file, 'rb') as file: PatchByteArray(data := bytearray(file.read()))

    output_file = sys.argv[2] if len(sys.argv) > 2 else exit() # discard patched data if output_file is omitted
    with open(output_file, "wb") as file: file.write(data) and print(f"[+] Saved to {output_file}")

def FindRegHex(reghex, data):
    regex = bytes(re.sub(r"\b([0-9a-fA-F]{2})\b", r"\\x\1", reghex), 'utf-8') # escape hex bytes
    return re.finditer(regex.replace(b' ', b''), data, re.DOTALL) # remove all spaces

def FindRegHexOnce(reghex, data): return next(FindRegHex(reghex, data), None)

def PatchByteSlice(patched, offset = 0, end = None):
    refs, file = {}, FileInfo(patched[offset : end], offset) # reset refs for each file
    for fix in FindFixes(file): ApplyFix(fix, patched, file, refs)

def ApplyFix(fix, patched, file, refs, match = None, fn_o = None):
    # if not fix.test: return # for testing any fix
    for match in FindRegHex(fix.reghex, file.data):
        for i in range(1, match.lastindex + 1) if match.lastindex else range(1): # loop through all matched groups
            p0 = p = Position(file, offset=match.start(i)) # offset is -1 when a group is not found
            if p0.address == None: continue # skip if p0 is not in a section
            if fix.look_behind or (i > 0 and len(match.group(i)) == 4): # find referenced address from any 4-byte group
                p = Position(file, address=Ref2Address(p0.address, file.data[p0.offset-8 : p0.offset+4], file.arch))
            p_info = p0.info + " -> " + (p.info if p.address != p0.address else '').ljust(len(p0.info)) # keep length unchanged for output alignment
            if not fix.look_behind:
                refs[p0.address] = fix.name if i == 0 else '.'.join(fix.name.split('.')[0:i+1:i]) # extract part 0 and part i from fix.name if i > 0
                if not refs.get(p.address): refs[p.address] = fix.name.split('.')[i] # extract part i from fix.name
                if p.file_o and fix.patch: PatchAtOffset(p.file_o, patched, fix.patch, i, p_info, refs[p0.address])
            elif 1 < len(ref := refs.get(p0.address, '.' + refs.get(p.address, ''))): # look behind if p0 or p is in refs
                fn = Position(file, offset=LastFunction(file.data[0 : p0.offset], file.arch)) # find function containing this match
                print("[-] Found fn " + ['.' * len(fn.info), fn.info][fn_o != (fn_o := fn.offset)] + f" <- {p_info} {ref}") # show fn.info when a new function is found
    if fix.patch and not match: print(f"[!] Cannot find pattern: {fix.name} {fix.reghex}")

def PatchAtOffset(file_o, patched, patch, i, p_info, ref):
    if (b := bytes.fromhex(patch[i-1] if isinstance(patch, list) else patch)): print(f"[+] Patch at {p_info} {ref} = {b.hex(' ')}") # use the whole fix.patch if it's not a list
    patched[file_o : file_o + len(b)] = b

AMD64, ARM64 = 'amd64', 'arm64' # arch x86-64, arch AArch64

def LastFunction(data, arch, last = None):
    function_reghex = { # reghex for function epilogue and function prologue
        AMD64:  r"(?:(?:C3|EB .|[E8 E9] .{4}) [66]*(?:90|CC|0F 0B|0F 1F [00 40 44 80 84] [00]*)* | 00{8})" ## (ret | jmp ? | call ?) (nop | int3 | ud2)
              + r"( (48 89 54 24 .)? ( [53 55-57] | 41 [54-57] | 48 8B EC | 48 89 E5 | 48 [81 83] EC )+ )", ## mov qword[rsp+?], rdx; (push r? | mov rbp, rsp | sub rsp, ?)
        ARM64:  r"(?:(?:C0 03 5F D6 | .{3} [14 17 94 97]) (?:1F 20 03 D5)* | 00{8}) ((. 03 1E AA  .{3} [94 97]  FE 03 . AA)?" ## mov x?, x30 ; bl ? ; mov x30, x? 
              + r"( FF . . D1 | [F4 F6 F8 FA FC FD] . . [A9 F9] | [E9 EB] . . 6D | FD . . 91 )+)", ## sub sp, sp, ? ; stp x?, x?, [sp + ?] ; add x29, sp, ?
    }[arch] # die on unknown arch
    for m in FindRegHex(function_reghex, data): last = m
    return last.start(1) if last else None

class Position:
    def __init__(self, file, address = None, offset = None):
        self.address = address if address != None else ConvertBetweenAddressAndOffset(file.offset2address, offset)
        self.offset = offset if offset != None else ConvertBetweenAddressAndOffset(file.address2offset, address)
        self.file_o = self.offset + file.base_offset if self.offset != None else None
        self.info = f"a:0x{self.address or 0:04x} " + (f"o:0x{self.file_o:06x}" if self.file_o else ' ' * 6)

def Ref2Address(base, byte_array, arch):
    if arch == ARM64 and base % 4 == 0: # PC relative instructions of arm64
        (instr3, instr, instr2) = struct.unpack("<3L", byte_array[-4*3:]) # 2 unsigned long in little-endian
        extend_sign = lambda number, msb: number - (1 << (msb+1)) if number >> msb else number
        if (m := FindRegHexOnce(r"[90 B0 D0 F0] (.{3} [^91])? .{3} 91$", byte_array)): # ADRP & ADD instructions
            if m.group(1): instr = instr3
            value64 = ((instr & 0x60000000) >> 29 | (instr & 0xffffe0) >> 3) << 12 # PAGE_SIZE = 0x1000 = 4096
            imm12 = (instr2 & 0x3ffc00) >> 10
            if instr2 & 0xc00000: imm12 <<= 12
            page_address = base >> 12 << 12 # clear 12 LSB
            return page_address + extend_sign(value64, 32) + imm12
        elif FindRegHexOnce(r"[80-9F] 52$", byte_array): # MOV instruction
            return instr2 >> 5 & ((1 << 16) - 1) # discard 11 MSB, discard 5 LSB
        elif FindRegHexOnce(r"[80-9F] 12$", byte_array): # MOVN instruction
            return ~(instr2 >> 5 & ((1 << 16) - 1)) # discard 11 MSB, discard 5 LSB
        elif (m := FindRegHexOnce(r"[80-9F] 52  (.{3} [^72])? . . [A0-BF] 72$", byte_array)): # MOV & MOVK instruction
            if m.group(1): instr = instr3
            immlo = instr >> 5 & ((1 << 16) - 1) # discard 11 MSB, discard 5 LSB
            immhi = instr2 >> 5 & ((1 << 16) - 1) # discard 11 MSB, discard 5 LSB
            return (immhi << 16) + immlo
        elif FindRegHexOnce(r"[94 97 14 17]$", byte_array): # BL / B instruction
            address = instr2 << 2 & ((1 << 28) - 1) # discard 6 MSB, append 2 zero LSB
            return base + extend_sign(address, 27)
        elif FindRegHexOnce(r"[10 30 50 70]$", byte_array): # ADR instruction
            immhi = instr2 >> 5 & ((1 << 19) - 1) # discard 8 MSB, discard 5 LSB
            immlo = instr2 >> 29 & ((1 << 2) - 1) # discard 1 MSB, discard 29 LSB
            return base + extend_sign(immhi << 2 + immlo, 20)
    elif arch == AMD64: # RVA & VA instructions of x64
        if FindRegHexOnce(r"(66 C7 84 . .{4} | 66 C7 44 . .)$", byte_array[:-4]):
            return struct.unpack("<h", byte_array[-4:-2])[0] # 2-byte integer
        (address,) = struct.unpack("<l", byte_array[-4:]) # address size is 4 bytes
        if FindRegHexOnce(r"(([48 4C] 8D | 0F 10) [05 0D 15 1D 25 2D 35 3D] | [E8 E9])$", byte_array[:-4]):
            return base + 4 + address # RVA reference is based on next instruction (which OFTEN is at the next 4 bytes)
        if FindRegHexOnce(r"([B8-BB BD-BF] | [8A 8D] [80-84 86-8C 8E-94 96-97] | 81 [C1 C5-C7 F8-FF] | 8D 8C 24 | 8D 9C 09 | 48 81 7D . | 48 81 7C 24 . | 48 C7 06 | (48 C7 05|C7 85|C7 84 .) .{4} | C7 44 . . | 3D)$", byte_array[:-4]):
            return address # VA reference
    return base # return the input address if referenced address is not found

def FindFixes(file):
    detected = set()
    for fix in Fixes.detections:
        for m in FindRegHex(fix.reghex, file.data):
            detected |= set([ fix.name, *m.groups() ]) # combine all matched detections
            print(f"\n[-] Spotted at {Position(file, offset=m.start()).info} {fix.name} {m.groups()} in {m.group(0)}")
    for tags, fixes in Fixes.tagged_fixes:
        if set(tags) == detected: return [fix for fix in fixes if fix.arch in [None, file.arch]] # filter out different arch
    exit("[!] Cannot find fixes for target file")

def PatchByteArray(data):
    (magic, num_archs) = struct.unpack(">2L", data[:4*2])
    if magic == 0xCAFEBABE: # FAT_MAGIC of MacOS universal binary
        for header_o in range(4*2, 4*2 + num_archs * (header_s := 4*5), header_s):
            (cpu_type, cpu_subtype, offset, size, align) = struct.unpack(">5L", data[header_o : header_o + header_s])
            print(f"\n[+] ---- at 0x{offset:x}: Executable for " + (arch := { 0x1000007: AMD64, 0x100000c: ARM64 }[cpu_type])) # die on unknown arch
            # with open(sys.argv[1] + "_" + arch, "wb") as f: f.write(data[offset : offset + size]) # store detected file
            # PatchByteSlice(data[offset : offset + size]) # patch detected executable as if it were stored in a separate file
            PatchByteSlice(data, offset, offset + size) # if arch == ARM64 else None
    else: PatchByteSlice(data)

def FileInfo(data = b'', base_offset = 0): # FileInfo is a singleton object
    if re.search(b"^MZ", data):
        import pefile # pip3 install pefile
        pe = pefile.PE(data=data, fast_load=True)
        FileInfo.arch = { 0x8664: AMD64, 0xAA64: ARM64 }[pe.FILE_HEADER.Machine] # die on unknown arch
        sections = [(pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
    elif re.search(b"^\x7FELF", data):
        from elftools.elf.elffile import ELFFile # pip3 install pyelftools
        elf = ELFFile(io.BytesIO(data))
        FileInfo.arch = { 'EM_X86_64': AMD64, 'EM_AARCH64': ARM64 }[elf.header['e_machine']] # die on unknown arch
        sections = [(s.header['sh_addr'], s.header['sh_offset'], s.header['sh_size']) for s in elf.iter_sections()]
    elif re.search(b"^\xCF\xFA\xED\xFE", data):
        from macho_parser.macho_parser import MachO # pip3 install git+https://github.com/Destitute-Streetdwelling-Guttersnipe/macho_parser.git
        macho = MachO(mm=data) # macho_parser was patched to use bytearray (instead of reading from file)
        FileInfo.arch = { 0x1000007: AMD64, 0x100000c: ARM64 }[macho.get_header().cputype] # die on unknown arch
        sections = [(s.addr, s.offset, s.size) for s in macho.get_sections()]
    else: exit("[!] Cannot detect file type")
    FileInfo.address2offset = sorted([(addr, o, size) for addr, o, size in sections if addr and o], reverse=True) # sort by address
    FileInfo.offset2address = sorted([(o, addr, size) for addr, o, size in sections if addr and o], reverse=True) # sort by offset
    FileInfo.data, FileInfo.base_offset = data, base_offset
    return FileInfo

def ConvertBetweenAddressAndOffset(sections, position):
    for start, other_start, size in sections:
        if position != None and start <= position < start + size: return position - start + other_start

if __name__ == "__main__": main()
