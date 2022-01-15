credits = "RegHex Patcher by Destitute-Streetdwelling-Guttersnipe (Credits to leogx9r & rainbowpigeon for signatures and patching logic)"
import re, sys, struct, io
import patches as Fixes

def main():
    print(f"[-] ---- {credits}")
    input_file = sys.argv[1] if len(sys.argv) > 1 else exit(f"Usage: {sys.argv[0]} input_file [output_file]")
    output_file = sys.argv[2] if len(sys.argv) > 2 else input_file
    PatchFile(input_file, output_file)

def PatchFile(input_file, output_file):
    with open(input_file, 'rb') as file: data = bytearray(file.read())
    SplitFatBinary(data)
    with open(output_file, "wb") as file: file.write(data)
    print(f"[+] Patched file saved to {output_file}")

def FindRegHex(reghex, data, onlyOnce = False):
    regex = bytes(re.sub(r"\b([0-9a-fA-F]{2})\b", r"\\x\1", reghex), 'utf-8') # escape hex bytes
    it = re.finditer(regex.replace(b' ', b''), data, re.DOTALL) # remove all spaces
    return next(it, None) if onlyOnce else it

def Patch(patched, file):
    for fix in FindFixes(file): PatchFix(fix, patched, file)

def PatchFix(fix, patched, file, match = None, last_o = None, refs = {}): # refs is not reset to default value in next calls
    for match in FindRegHex(fix.reghex, file.data):
        for i in range(1, match.lastindex + 1) if match.lastindex else range(1):
            p0 = p = Position(file, offset=match.start(i))
            if p0.address != None and (fix.look_behind or (i > 0 and len(match.group(i)) == 4)):
                p = Position(file, address=Ref2Address(p0.address, file.data[p0.offset-4 : p0.offset+4], file.arch))
            p_info = f"{p0.info} -> {p.info if p.address != p0.address else ' ' * len(p0.info)}"
            if not fix.look_behind:
                refs[p0.address] = fix.name if i == 0 else '.'.join(fix.name.split('.')[0:i+1:i])
                if not refs.get(p.address): refs[p.address] = fix.name.split('.')[i] # p0.address can be equal to p.address when ref not exist
                if patch := bytes.fromhex(fix.patch[i-1] if isinstance(fix.patch, list) else fix.patch): # use the whole fix.patch if it's not a list
                    print(f"[+] Patch at {p_info} {refs[p0.address]} = {patch.hex(' ')}")
                    if p.file_o: patched[p.file_o : p.file_o + len(patch)] = patch
            elif p0.address != None and 1 < len(ref := refs.get(p0.address, '.' + refs.get(p.address, ''))):
                for m in FindRegHex(function_prologue_reghex[file.arch], file.data[0 : p0.offset]):
                    if len(m.group(0)) > 1: o = m.start() # NOTE: skip too short match to exclude false positive
                print(f"[-] Found {['..', 'fn'][o != last_o]} {Position(file, offset=(last_o := o)).info} <- {p_info} {ref}")
    if fix.patch and not match: print(f"[!] Can not find pattern: {fix.name} {fix.reghex}")

AMD64 = 'amd64' # arch x86-64
ARM64 = 'arm64' # arch AArch64

function_prologue_reghex = {
    AMD64:  r"( [53 55-57] | 41 [54-57] | 48 8B EC | 48 89 E5 )+" ## push r?x ; push r1? ; mov rbp, rsp ; mov rbp, rsp
          + r"(48 [81 83] EC)?", ## sub rsp, ?,
    ARM64:  r"(. 03 1E AA  .{3} [94 97]  FE 03 . AA)?" ## mov x?, x30 ; bl ? ; mov x30, x? 
          + r"( FF . . D1 | [F4 F6 F8 FA FC FD] . . A9 | [E9 EB] . . 6D | FD . . 91 )+", ## sub sp, sp, ? ; stp x?, x?, [sp + ?] ; add x29, sp, ?
}

class Position:
    def __init__(self, file, address = None, offset = None):
        self.address = address if address != None else ConvertBetweenAddressAndOffset(file.offset2address, offset)
        self.offset = offset if offset != None else ConvertBetweenAddressAndOffset(file.address2offset, address)
        self.file_o = self.offset + file.base_offset if self.offset != None else None
        self.info = f"a:0x{self.address or 0:06x} " + (f"o:0x{self.file_o:06x}" if self.file_o else ' ' * 10)

def Ref2Address(base, byte_array, arch):
    if arch == ARM64: # PC relative instructions of arm64
        extend_sign = lambda number, msb: number - (1 << (msb+1)) if number >> msb else number
        if FindRegHex(r"[90 B0 D0 F0] .{3} 91$", byte_array, onlyOnce=True): # ADRP & ADD instructions
            (instr, instr2) = struct.unpack("<2L", byte_array) # 2 unsigned long in little-endian
            immlo = (instr & 0x60000000) >> 29
            immhi = (instr & 0xffffe0) >> 3
            value64 = (immlo | immhi) << 12 # PAGE_SIZE = 0x1000 = 4096
            imm12 = (instr2 & 0x3ffc00) >> 10
            if instr2 & 0xc00000: imm12 <<= 12
            page_address = base >> 12 << 12 # clear 12 LSB
            return page_address + extend_sign(value64, 33) + imm12
        elif FindRegHex(r"[94 97 14 17]$", byte_array, onlyOnce=True): # BL / B instruction
            address = struct.unpack("<L", byte_array[4:])[0] << 2 & ((1 << 28) - 1) # discard 6 MSB, append 2 zero LSB
            return base + extend_sign(address, 27)
        elif FindRegHex(r"[10]$", byte_array, onlyOnce=True): # ADR instruction
            address = struct.unpack("<L", byte_array[4:])[0] >> 3 & ((1 << 21) - 1) # discard 8 MSB, discard 3 LSB
            return base + extend_sign(address, 20)
    elif arch == AMD64: # RVA & VA instructions of x64
        address = struct.unpack("<l", byte_array[4:])[0] # address size is 4 bytes
        if FindRegHex(r"(([48 4C] 8D | 0F 10) [05 0D 15 1D 25 2D 35 3D] | [E8 E9])$", byte_array[:4], onlyOnce=True):
            return base + 4 + address # RVA reference is based on next instruction (which OFTEN is at the next 4 bytes)
        if FindRegHex(r"([B8-BB BD-BF] | [8A 8D] [80-84 86-8C 8E-94 96-97] | 81 [C5-C7 FC-FF] | 8D 8C 24)$", byte_array[:4], onlyOnce=True):
            return address # VA reference
    return base

def FindFixes(file):
    detected = set()
    for fix in Fixes.detections:
        for m in FindRegHex(fix.reghex, file.data):
            detected |= set([ fix.name, *m.groups() ])
            print(f"\n[-] Spotted at {Position(file, offset=m.start()).info} {fix.name} {m.groups()} in {m.group(0)}")
    for tags, fixes in Fixes.tagged_fixes:
        if set(tags) == detected: return [fix for fix in fixes if not fix.arch or fix.arch == file.arch] # filter out different arch
    exit("[!] Can not find fixes for target file")

def SplitFatBinary(data):
    (magic, num_archs) = struct.unpack(">2L", data[:4*2])
    if magic == 0xCAFEBABE: # MacOS universal binary
        for i in range(num_archs):
            # with open(f"macho_executable{i}", "wb") as file: file.write(data)
            header_offset = 4*2 + 4*5*i # header_size = 4*5
            (cpu_type, cpu_subtype, offset, size, align) = struct.unpack(">5L", data[header_offset : header_offset + 4*5])
            print(f"\n[+] ---- at 0x{offset:x}: Executable for CPU 0x{cpu_type:x} 0x{cpu_subtype:x}")
            Patch(data, FileInfo(data[offset : offset + size], offset))
    else:
        Patch(data, FileInfo(data[:]))

def FileInfo(data = b'', base_offset = 0):
    if re.search(b"^MZ", data):
        import pefile
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
    else:
        exit("[!] Can not detect file type")
    FileInfo.address2offset = sorted([(addr, offset, size) for addr, offset, size in sections if addr and offset], reverse=True) # sort by address
    FileInfo.offset2address = sorted([(offset, addr, size) for addr, offset, size in FileInfo.address2offset], reverse=True) # sort by offset
    FileInfo.data, FileInfo.base_offset = data, base_offset
    return FileInfo

def ConvertBetweenAddressAndOffset(sections, position):
    for start, converted_start, size in sections:
        if start <= position < start + size: return position - start + converted_start
    return None

if __name__ == "__main__": main()
