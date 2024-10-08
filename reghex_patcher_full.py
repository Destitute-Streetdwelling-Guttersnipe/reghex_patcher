#!/usr/bin/env python3
credits = "RegHex Patcher by Destitute-Streetdwelling-Guttersnipe (Thanks to leogx9r & rainbowpigeon for inspiration)"
import re, sys, struct, io, patches as Fixes

def main(argv):
    if len(argv) <= 1: exit(f"[-] ---- {credits}\nUsage: {argv[0]} [input_file [output_file]]")
    if (onlyTest := argv[1] == '-t'): argv.remove('-t') # only use fixes with test=True (if option '-t' exists)

    input_file = argv[1] if argv[1] != '-' else sys.stdin.fileno() # read from stdin if input_file is a hyphen
    with open(input_file, 'rb') as file: UnpackAndPatch(data := bytearray(file.read()), onlyTest)

    output_file = argv[2] if len(argv) > 2 else exit() # discard patched data if output_file is omitted
    with open(output_file, "wb") as file: file.write(data) and print(f"[+] Saved to {output_file}")

def FindRegHex(reghex, data):
    regex = bytes(re.sub(r"\b([0-9a-fA-F]{2})\b", r"\\x\1", reghex), 'utf-8') # escape hex bytes
    return re.finditer(regex.replace(b' ', b''), data, re.DOTALL) # remove all spaces

def FindRegHexOnce(reghex, data): return next(FindRegHex(reghex, data), None)

def PatchByteSlice(patched, offset = 0, end = None, onlyTest = False):
    refs, file = {}, FileInfo(patched[offset : end], offset) # reset refs for each file
    for fix in FindFixes(file): ApplyFix(fix, patched, file, refs) if onlyTest in [False, fix.test] else None # only use fixes with test=True (if option '-t' exists)

def ApplyFix(fix, patched, file, refs, match = None, fn = None, ref0 = None):
    for match in FindRegHex(fix.reghex, file.data):
        for i in range(1, len(match.groups()) + 1) or range(1): # loop through all matched groups
            p0 = p = Position(file, offset=match.start(i)) # offset is -1 when a group is not found
            if p0.address and (fix.look_behind or (i > 0 and len(match.group(i)) == 4)): # find referenced address from any 4-byte group
                p = Position(file, address=Ref2Address(p0.address, p0.offset, file))
            if p0.address and not fix.look_behind:
                h = ''.join(fix.patch[i-1:i]) if isinstance(fix.patch, list) else fix.patch # non-existent element in array fix.patch is considered to be an empty string
                if not refs.get(p.address) and h == '\r': break # skip a match if referenced address is not found earlier and its patch is '\r'
                ref0 = refs[p0.address] = fix.name if i == 0 else '.'.join(fix.name.split('.')[0:i+1:i]) # extract part 0 and part i from fix.name if i > 0
                if not refs.get(p.address): refs[p.address] = '.'+fix.name.split('.')[i] # extract part i from fix.name
                if p.address == p0.address: ref0 += f" : {match.group(i).hex(' ')}" # show matched bytes unless referenced address is found from match bytes
                if fix.patch != '': PatchAtOffset(p.offset, file, patched, h, p.ref_info(p0, ref0))
            else: fn = FindNearestFunction(file, refs, p0, p, fn)
    if fix.patch != '' and (not match or not ref0): print(f"[!] Cannot find pattern: {fix.name} {fix.reghex}")

def FindNearestFunction(file, refs, p0, p, fn):
    if (ref0 := refs.get(p0.address)) or (ref := refs.get(p.address)): # look behind if p0 or p is in refs
        diff = fn != (fn := LastFunction(file, fn or Position(file, offset=0), p0)) # find function containing this match
        print("[-] Found fn " + ['-' * len(fn.info), fn.info][diff] + f" <- {p.ref_info(p0, ref0 or '-'+ref)}") # show fn.info when a new function is found
    return fn

def PatchAtOffset(offset, file, patched, h, ref_info):
    print(f"[+] Patch at {ref_info} => {h}" if len(h)>=2 else f"[-] Found at {ref_info}")
    if (b := bytes.fromhex(h)) and offset: patched[(o := offset + file.base_offset) : o + len(b)] = b # has no effect if h is empty or h contains spaces

AMD64, ARM64 = 'amd64', 'arm64' # arch x86-64, arch AArch64

def LastFunction(file, start, end, last = None): # file: FileInfo, start: Position, end: Position
    function_reghex = { # reghex for function epilogue and function prologue
        AMD64:  r"(?:(?:C3|EB .|[E8 E9] .{4}) [66]*(?:90|CC|0F 0B|0F 1F [00 40 44 80 84] [00]*)* | 00{8})" ## (ret | jmp ? | call ?) (nop | int3 | ud2)
              + r"( (48 89 54 24 .)? ( [53 55-57] | 41 [54-57] | 48 8B EC | 48 89 E5 | 48 [81 83] EC )+ )", ## mov qword[rsp+?], rdx; (push r? | mov rbp, rsp | sub rsp, ?)
        ARM64:  r"(?:(?:C0 03 5F D6 | .{3} [14 17 94 97]) (?:1F 20 03 D5)* | 00{8}) ((. 03 1E AA  .{3} [94 97]  FE 03 . AA)?" ## mov x?, x30 ; bl ? ; mov x30, x? 
              + r"( FF . . D1 | [F4 F6 F8 FA FC FD] . . [A9 F9] | [E9 EB] . . 6D | FD . . 91 )+)", ## sub sp, sp, ? ; stp x?, x?, [sp + ?] ; add x29, sp, ?
    }[file.arch] # die on unknown arch
    for m in FindRegHex(function_reghex, file.data[start.offset:end.offset]): last = m
    return Position(file, offset=start.offset + last.start(1)) if last else start

class Position:
    def __init__(self, file, address = None, offset = None):
        a = self.address = address if address != None else ConvertOffsetToAddress(file.sections, offset)
        o = self.offset = offset if offset != None else ConvertAddressToOffset(file.sections, address)
        self.info = f"a:{a or 0:6x} " + (f"o:{o + file.base_offset:6x}" if o else '')
    def ref_info(self, p0, ref):
        return f"{p0.info} -> {self.info if self.address != p0.address else '':{len(p0.info)}} {ref}" # keep length unchanged for output alignment

def Ref2Address(base, offset, file):
    byte_array = file.data[offset-8 : offset+4]
    if file.arch == ARM64 and base % 4 == 0: # PC relative instructions of arm64
        (instr2,) = struct.unpack("<L", byte_array[-4:]) # 2 unsigned long in little-endian
        extend_sign = lambda number, msb: number - (1 << (msb+1)) if number >> msb else number
        bits2number = lambda bits, skips, count: (bits >> skips) & ((1 << count) - 1) # skip some LSB and extract some bits
        if m := FindRegHexOnce(r"(.{3} [90 B0 D0 F0]) (.{3} [^91])? .{3} 91$", byte_array): # ADRP & ADD instructions
            (instr,) = struct.unpack("<L", m.group(1))
            page_offset = (bits2number(instr, 5, 19) << 2) + bits2number(instr, 29, 2) # PAGE_SIZE = 0x1000 = 4096
            imm12 = bits2number(instr2, 10, 12)
            if instr2 & 0x400000: imm12 <<= 12
            page_address = base >> 12 << 12 # clear 12 LSB
            return page_address + extend_sign(page_offset << 12, 32) + imm12
        elif m := FindRegHexOnce(r"[80-9F] (?:(12)|52)$", byte_array): # MOVN/MOV instruction
            value = bits2number(instr2, 5, 16) # discard 11 MSB, discard 5 LSB
            return ~value if m.group(1) else value # invert bits in case of MOVN
        elif m := FindRegHexOnce(r"(. . [80-9F] 52)  (.{3} [^72])? . . [A0-BF] 72$", byte_array): # MOV & MOVK instruction
            (instr,) = struct.unpack("<L", m.group(1))
            return (bits2number(instr2, 5, 16) << 16) + bits2number(instr, 5, 16)
        elif FindRegHexOnce(r"[94 97 14 17]$", byte_array): # BL / B instruction
            address = bits2number(instr2, 0, 26) << 2 # discard 6 MSB, append 2 zero LSB
            return base + extend_sign(address, 27)
        elif FindRegHexOnce(r"[10 30 50 70]$", byte_array): # ADR instruction
            address = (bits2number(instr2, 5, 19) << 2) + bits2number(instr2, 29, 2)
            return base + extend_sign(address, 20)
    elif file.arch == AMD64: # RVA & VA instructions of x64
        if FindRegHexOnce(r"48 [B9 BA]", byte_array[:-4]):
            return struct.unpack("<q", file.data[offset:offset+8])[0] # 8-byte integer
        if FindRegHexOnce(r"(66 C7 05 .{4}|66 C7 84 . .{4} | 66 C7 44 . .)$", byte_array[:-4]):
            return struct.unpack("<h", byte_array[-4:-2])[0] # 2-byte integer
        (address,) = struct.unpack("<l", byte_array[-4:]) # address size is 4 bytes
        if FindRegHexOnce(r"(([48 4C] [89 8D] | [88 8A] | 0F [10 11 28 7F]) [05 0D 15 1D 25 2D 35 3D] | [E8 E9])$", byte_array[:-4]):
            return base + 4 + address # RVA reference is based on next instruction (which OFTEN is at the next 4 bytes)
        if FindRegHexOnce(r"(83 25 | C6 05)$", byte_array[:-4]):
            return base + 5 + address # RVA reference is based on next instruction (which OFTEN is at the next 5 bytes)
        if FindRegHexOnce(r"(C7 05)$", byte_array[:-4]):
            return base + 8 + address # RVA reference is based on next instruction (which OFTEN is at the next 8 bytes)
        if FindRegHexOnce(r"([B8-BB BD-BF] | [8A 8D] [80-84 86-8C 8E-94 96-97] | 81 [C1 C5-C7 F8-FF] | 8D 8C 24 | 8D 9C 09 | 48 81 7D . | 48 81 7C 24 . | 48 C7 06 | (C7 [05 83 85-87]|C7 84 24) .{4} | C7 44 . . | 3D | 0F B6 [88 B0] | 48 69 C0)$", byte_array[:-4]):
            return address # VA reference
    return base # return the input address if referenced address is not found

def FindFixes(file):
    detected = { file.arch, file.os }
    for fix in Fixes.detections:
        for m in FindRegHex(fix.reghex, file.data):
            detected |= { fix.name, *m.groups() } # combine all matched detections
            print(f"[-] ---- at {Position(file, offset=m.start()).info} {fix.name} {m.groups()} in {m.group(0)}\n")
    fixes = [fixes for tags, fixes in Fixes.tagged_fixes if set(tags).issubset(detected)] # combine tagged_fixes that is subset of detected list
    return [fix for fix in sum(fixes, []) if fix.arch in [None, file.arch] and fix.os in [None, file.os]] # filter out different arch & os

def UnpackAndPatch(data, onlyTest = False):
    (magic, num_archs) = struct.unpack(">2L", data[:(start := 4*2)]) if len(data) >= 4*2 else (0, 0)
    if magic == 0xCAFEBABE: # FAT_MAGIC of MacOS universal binary
        while (num_archs := num_archs - 1) >= 0:
            (cpu_type, _, offset, size, _) = struct.unpack(">5L", data[start : (start := start + 4*5)])
            PatchByteSlice(data, offset, offset + size, onlyTest) # if cpu_type == 0x100000c else None
    else: PatchByteSlice(data, 0, None, onlyTest)

def FileInfo(data = b'', base_offset = 0): # FileInfo is a singleton object
    if re.search(b"^MZ", data):
        import pefile # pip3 install pefile
        FileInfo.os, pe = 'windows', pefile.PE(data=data, fast_load=True)
        FileInfo.arch = { 0x8664: AMD64, 0xAA64: ARM64 }[pe.FILE_HEADER.Machine] # die on unknown arch
        FileInfo.sections = [(pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
    elif re.search(b"^\x7FELF", data):
        from elftools.elf.elffile import ELFFile # pip3 install pyelftools
        FileInfo.os, elf = 'linux', ELFFile(io.BytesIO(data))
        FileInfo.arch = { 'EM_X86_64': AMD64, 'EM_AARCH64': ARM64 }[elf.header['e_machine']] # die on unknown arch
        FileInfo.sections = [(s.header['sh_addr'], s.header['sh_offset'], s.header['sh_size']) for s in elf.iter_sections()]
    elif re.search(b"^\xCF\xFA\xED\xFE", data):
        from macho_parser.macho_parser import MachO # pip3 install git+https://github.com/Destitute-Streetdwelling-Guttersnipe/macho_parser.git
        FileInfo.os, macho = 'osx', MachO(mm=data) # macho_parser was patched to use bytearray (instead of reading from file)
        FileInfo.arch = { 0x1000007: AMD64, 0x100000c: ARM64 }[macho.get_header().cputype] # die on unknown arch
        FileInfo.sections = [(s.addr, s.offset, s.size) for s in macho.get_sections()]
        # with open(sys.argv[1] + "_" + FileInfo.arch, "wb") as f: f.write(data) # store detected file
    else: exit("[!] ---- Cannot detect file type: " + data[:8].hex(' '))
    print(f"\n[+] ---- at o:{base_offset:x} Executable for {FileInfo.os} {FileInfo.arch}")
    FileInfo.data, FileInfo.base_offset = data, base_offset
    return FileInfo

def ConvertAddressToOffset(sections, position): return ConvertOffsetToAddress(sections, position, src=0, dst=1)
def ConvertOffsetToAddress(sections, position, src=1, dst=0, size=2): # 0 is index of address, 1 is index of offset
    for s in sections:
        if position and s[src] and 0 <= position - s[src] < s[size]: return position - s[src] + s[dst]

if __name__ == "__main__": main(sys.argv)
