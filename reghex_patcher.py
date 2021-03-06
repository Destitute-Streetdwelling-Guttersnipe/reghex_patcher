credits = "[-] ---- RegHex Patcher by Destitute-Streetdwelling-Guttersnipe (Credits to leogx9r & rainbowpigeon for signatures and patching logic)"

import re, sys

def main():
    print(credits)
    input_file = sys.argv[1] if len(sys.argv) > 1 else exit(f"Usage: {sys.argv[0]} input_file output_file")
    output_file = sys.argv[2] if len(sys.argv) > 2 else input_file
    PatchFile(input_file, output_file)

def PatchFile(input_file, output_file):
    with open(input_file, 'rb') as file:
        data = bytearray(file.read())
    Patch(data)
    with open(output_file, "wb") as file:
        file.write(data)
    print(f"[+] Patched file saved to {output_file}")

def FindRegHex(fix, data, showMatchedText = False):
    regex = bytes(re.sub(r"\b([0-9a-fA-F]{2})\b", r"\\x\1", fix.reghex), encoding='utf-8') # escape hex bytes
    matches = list(re.finditer(regex, data, re.DOTALL | re.VERBOSE))[:10] # only 10 matches
    for m in matches: print("[-] Found at {}: pattern {} {}".format(hex(m.start()), fix.name, m.group(0) if showMatchedText else ''))
    return matches

def Patch(data):
    for fix in FindFixes(data):
        matches = FindRegHex(fix, data)
        for match in matches:
            offset = match.start()
            if fix.is_ref: offset = RelativeOffset(offset, data)
            print(f"[+] Patch at {hex(offset)}: {fix.patch}")
            patch = bytes.fromhex(fix.patch)
            data[offset : offset + len(patch)] = patch
        print(f"[!] Can not find pattern: {fix.name} {fix.reghex}\n" if len(matches) == 0 else '')

def RelativeOffset(offset, data):
    relative_address = int.from_bytes(data[offset : offset + 4], byteorder='little') # address size is 4 bytes
    return (offset + 4 + relative_address) & 0xFFFFFFFF

def FindFixes(data):
    detected = set()
    for fix in Fixes.detections:
        for m in FindRegHex(fix, data, True):
            detected |= set([ fix.name, *m.groups() ])
    print(f"[+] Detected tags: {detected}\n")
    for tags, fixes in Fixes.tagged_fixes:
        if set(tags) == detected: return fixes
    exit("[!] Can not find fixes for target file")

# this class can be extracted into a file
class Fixes:
    import collections

    # for x64 CPU
    nop5 = "90 " * 5 # nop over E8 .{4} (call [dword])
    ret = "C3" # ret
    ret0 = "48 31 C0 C3" # xor rax, rax; ret
    ret1 = "48 31 C0 48 FF C0 C3" # xor rax, rax; inc rax; ret
    ret119 = "48 C7 C0 19 01 00 00 C3" # mov rax, 0x119; ret
    # for ARM64 CPU
    _ret = "C0 03 5F D6" # ret
    _ret0 = "E0 03 1F AA C0 03 5F D6" # mov x0, xzr; ret
    _nop = "1F 20 03 D5" # nop

    Fix = collections.namedtuple('Fix', 'name reghex patch is_ref', defaults=('', '', nop5, False)) # reghex is regex with hex bytes

    st_wind_fixes = [
        Fix(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . . . .", patch=ret0, is_ref=True),
        Fix(name="blacklist_check", reghex="(?<= . . . . . . ) E8 . . . . (48|49) . ."), # 48 for dev, 49 for stable
    ]
    st_linux_fixes = [
        Fix(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . . . .", patch=ret0, is_ref=True),
        Fix(name="blacklist_check", reghex="E8 . . . . . . . . . . . ."),
    ]
    st_macos_fixes = [
        Fix(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . . . .", patch=ret0, is_ref=True),
        Fix(name="blacklist_check", reghex="E8 . . . . . . . . . . . . . ."),
    ]
    st_macos_fixes_arm64 = [
        Fix(name="license_check", reghex=". . . . . . . .", patch=_ret0),
        Fix(name="blacklist_check", reghex=". . . . . . . . . . . . . . . . . . . .", patch=_nop),
    ]
    sm_wind_fixes = [
        Fix(name="server_validate", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . . .", patch=ret1),
        Fix(name="blacklist_check", reghex="(?<= . . . . . . ) E8 . . . . . . . . . ."),
    ]
    sm_linux_fixes = [
        Fix(name="server_validate", reghex="55 . . . . . . . . . . .", patch=ret1),
        Fix(name="blacklist_check", reghex="E8 . . . . . . . . . . . ."),
    ]
    sm_macos_fixes = [
        Fix(name="server_validate", reghex="55 . . . . . . . . . . . . . . . . .", patch=ret1),
        Fix(name="blacklist_check", reghex="E8 . . . . . . . . . . . . . ."),
    ]
    sm_macos_fixes_arm64 = [
        Fix(name="license_check", reghex=". . . . . . . .", patch=_ret0),
        Fix(name="blacklist_check", reghex=". . . . . . . . . . . . . . . . . . . .", patch=_nop),
    ]
    st_blacklist_fixes = [
        Fix(name="blacklisted_license_0D9497", reghex="97 94 0D 00", patch="00 00 00 00"), # EA7E-890007 TwitterInc
        Fix(name="license_server", reghex="license\.sublimehq\.com", patch=b"license.localhost.\x00\x00\x00".hex(' '))
    ]
    tagged_fixes = [
        ([b"x64", "SublimeText" ,            b"windows"], st_wind_fixes ),
        ([b"x64", "SublimeText" , b"arm64",  b"osx"    ], st_macos_fixes + st_macos_fixes_arm64),
        ([b"x64", "SublimeText" ,            b"linux"  ], st_linux_fixes),
        ([b"x64", "SublimeMerge",            b"windows"], sm_wind_fixes ),
        ([b"x64", "SublimeMerge", b"arm64",  b"osx"    ], sm_macos_fixes + sm_macos_fixes_arm64),
        ([b"x64", "SublimeMerge",            b"linux"  ], sm_linux_fixes),
        ([        "SublimeText" ,                      ], st_blacklist_fixes ),
        ([        "SublimeMerge",                      ], st_blacklist_fixes ),
    ]
    detections = [
        Fix(name="SublimeText", reghex=r"/updates/4/\w+_update_check\?version=\d+&platform=(\w+)&arch=(\w+)"), # arch: x64, arm64
        Fix(name="SublimeMerge", reghex=r"/updates/\w+_update_check\?version=\d+&platform=(\w+)&arch=(\w+)"), # platform: windows, osx, linux
        # Fix(name="SublimeText", reghex=r"/updates/4/\w+_update_check\?version=\d+&platform=\w+&arch=\w+"),
        # Fix(name="SublimeMerge", reghex=r"/updates/\w+_update_check\?version=\d+&platform=\w+&arch=\w+"),
    ]

if __name__ == "__main__":
    main()
