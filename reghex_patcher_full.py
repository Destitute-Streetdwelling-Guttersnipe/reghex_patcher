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

def FindRegHex(fix, data, showMatchedText = False):
    regex = bytes(re.sub(r"\b([0-9a-fA-F]{2})\b", r"\\x\1", fix.reghex), encoding='utf-8') # escape hex bytes
    matches = list(re.finditer(regex, data, re.DOTALL | re.VERBOSE))[:fix.count or 10] # only 10 matches
    for m in matches: print("[-] Found at {}: pattern {} {}".format(hex(m.start()), fix.name, m.group(0) if showMatchedText else ''))
    return matches

def Patch(data):
    sections = FileInfo(data)
    for fix in FindFixes(data):
        matches = FindRegHex(fix, data)
        for match in matches:
            offset = match.start()
            if fix.is_rva or fix.is_va or fix.is_pic: offset = Ref2Offset(offset, data, sections, fix.is_rva, fix.is_pic)
            print(f"[+] Patch at o:{hex(offset)} a:{hex(Offset2Address(sections, offset))}: {fix.patch}")
            patch = bytes.fromhex(fix.patch)
            data[offset : offset + len(patch)] = patch
        print(f"[!] Can not find pattern: {fix.name} {fix.reghex}\n" if len(matches) == 0 else '')
    return data

def Ref2Offset(offset, data, sections, is_rva, is_pic):
    # TODO: use byteorder from FileInfo(data)
    address = Bytes2Address(data[offset : offset + 4], is_rva, is_pic)
    if is_pic or is_rva:
        # return (offset + 4 + address) & 0xFFFFFFFF # NOTE: assume that referenced address is in the same section
        base = Offset2Address(sections, offset)
        address += base
    return Address2Offset(sections, address)

def Bytes2Address(byte_array, is_rva, is_pic):
    if is_pic:
        address = int.from_bytes(byte_array, byteorder='little', signed=False) << 2 & ((1 << 28) - 1) # append 2 zero LSB, discard 6 MSB
        if address >> 27: address -= 1 << 28 # extend sign from MSB (bit 27)
    else:
        address = int.from_bytes(byte_array, byteorder='little', signed=True) # address size is 4 bytes
        if is_rva: address += 4 # RVA is based on next instruction (which OFTEN is at the next 4 bytes)
    return address

def FindFixes(data):
    detected = set()
    for fix in Fixes.detections:
        for m in FindRegHex(fix, data, True):
            detected |= set([ fix.name, *m.groups() ])
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
            data[offset:offset + size] = Patch(data[offset:offset + size])
    else:
        data = Patch(data)

def FileInfo(data):
    sections = []
    if re.search(b"^MZ", data):
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        sections = [(s.VirtualAddress, s.PointerToRawData) for s in pe.sections]
    elif re.search(b"^\x7FELF", data):
        from elftools.elf.elffile import ELFFile # pip3 install pyelftools
        import io
        elf = ELFFile(io.BytesIO(data))
        sections = [(s.header['sh_addr'], s.header['sh_offset']) for s in elf.iter_sections()]
    elif re.search(b"^\xCF\xFA\xED\xFE", data):
        # with open("macho_executable", "wb") as file: file.write(data)
        from macho_parser.macho_parser import MachO # pip3 install git+https://github.com/Destitute-Streetdwelling-Guttersnipe/macho_parser.git
        macho = MachO(mm=data) # macho_parser was patched to use bytearray (instead of reading from file)
        sections = [(s.addr, s.offset) for s in macho.get_sections()]
        # print([f"{s.segname} a:{s.vmaddr:x} o:{s.fileoff:x}" for s in macho.get_segments()])
    else:
        print("[!] Can not read file sections")
    sections = [(s[0], s[1]) for s in sections if s[0] > 0 and s[1] > 0]
    # print("[-] sections(address,offset): " + " ".join([f"(0x{s[0]:x},0x{s[1]:x})" for s in sections]))
    return sections

def Address2Offset(sections, address):
    for s_address, s_offset in sorted(sections, key=lambda pair: pair[0], reverse=True): # sorted by address
        if address >= s_address:
            return address - s_address + s_offset
    print(f"[!] Address 0x{address:x} not found in sections")
    return address

def Offset2Address(sections, offset):
    for s_address, s_offset in sorted(sections, key=lambda pair: pair[1], reverse=True): # sorted by offset
        if offset >= s_offset:
            return offset - s_offset + s_address
    print(f"[!] Offset 0x{offset:x} not found in sections")
    return offset

if __name__ == "__main__":
    main()
