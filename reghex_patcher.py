credits = "[-] ---- RegHex Patcher by Destitute-Streetdwelling-Guttersnipe (Credits to leogx9r & rainbowpigeon for signatures and patching logic)"

import re

def PatchFile(input_file):
    with open(input_file, 'rb') as file:
        data = bytearray(file.read())
    Patch(data)
    with open(input_file, "wb") as file:
       file.write(data)
    print(f"[+] Patched file saved to {input_file}")

def FindRegHex(fix, data):
    matches = list(re.finditer(fix.reghex, data, re.DOTALL | re.VERBOSE))[:10] # only 10 matches
    if len(matches) == 0: return None
    for m in matches: print("[-] Found at {}: pattern {}".format(hex(m.start()), fix.name))
    return matches[0] 

def Patch(data):
    for fix in Fixes().Load(data):
        match = FindRegHex(fix, data)
        if not match: exit("[!] Can not find pattern: {} '{}'".format(fix.name, fix.reghex))
        offset = match.start()
        if fix.is_ref: offset = RelativeOffset(offset, data)
        print("[+] Patch at {}: {}\n".format(hex(offset), fix.patch.hex(' ')))
        data[offset : offset + len(fix.patch)] = fix.patch

def RelativeOffset(offset, data):
    relative_address = int.from_bytes(data[offset : offset + 4], byteorder='little') # address size is 4 bytes
    return (offset + 4 + relative_address) & 0xFFFFFFFF

class Fixes:
    nop5 = "90" * 5 # nop over E8 . . . . (call [dword])
    ret = "C3" # ret
    ret0 = "48 31 C0 C3" # xor rax, rax; ret
    ret1 = "48 31 C0 48 FF C0 C3" # xor rax, rax; inc rax; ret
    ret281 = "48 C7 C0 19 01 00 00 C3" # mov rax, 281; ret

    class Fix:
        nop5 = "90" * 5 # nop over E8 . . . . (call [dword])
        def __init__(self, name, reghex, patch=nop5, is_ref=False): # reghex is regex with hex bytes
            self.name = name
            self.reghex = bytes(re.sub(r"\b([0-9a-fA-F]{2})\b", r"\\x\1", reghex), encoding='utf-8') # escape hex bytes
            self.is_ref = is_ref
            self.patch = bytes.fromhex(patch)
    # NOTE: license_notify was said to use patch=ret0 !
    st_linux_fixes = [
        Fix(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . . . .", patch=ret0, is_ref=True),
        Fix(name="server_validate", reghex="55 . . . . . . . . . . .", patch=ret1),
        Fix(name="license_notify", reghex="41 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", patch=ret),
        Fix(name="crash_reporter", reghex="55 . . . . . . . . . . . . . . . . . . . . . .", patch=ret),
        Fix(name="blacklist_check", reghex="E8 . . . . . . . . . . . ."),
        Fix(name="license_recheck", reghex="E8 . . . . . . . . . . . . . . . ."),
    ]
    st_macos_fixes = [
        Fix(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . . . .", patch=ret0, is_ref=True),
        Fix(name="server_validate", reghex="55 . . . . . . . . . . . . . . . . .", patch=ret1),
        Fix(name="license_notify", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", patch=ret),
        Fix(name="crash_reporter", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . .", patch=ret),
        Fix(name="blacklist_check", reghex="E8 . . . . . . . . . . . . . ."),
        Fix(name="license_recheck", reghex="E8 . . . . . . . . . . . . . . . . . ."),
    ]
    st_wind_fixes = [
        Fix(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . . . .", patch=ret0, is_ref=True),
        Fix(name="server_validate", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . . .", patch=ret1),
        Fix(name="license_notify", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", patch=ret),
        Fix(name="crash_reporter", reghex="41 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", patch=ret),
        Fix(name="blacklist_check", reghex="(?<= . . . . . . ) E8 . . . . (48|49) . ."), # 48 for dev, 49 for stable
        Fix(name="license_recheck", reghex="(?<= . . . . . . ) E8 . . . . . . . . . (48|4C) . . ."), # 48 for dev, 4C for stable
    ]
    sm_linux_fixes = [
        Fix(name="server_validate", reghex="55 . . . . . . . . . . .", patch=ret1),
        Fix(name="license_notify", reghex="41 . . . . . . . . . . . . . . . . .", patch=ret),
        Fix(name="crash_reporter", reghex="55 . . . . . . . . . . . . . . . . . . . . . .", patch=ret),
        Fix(name="blacklist_check", reghex="E8 . . . . . . . . . . . ."),
        Fix(name="license_recheck", reghex="E8 . . . . . . . . . . . . . . . ."),
        Fix(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . .", patch=ret281, is_ref=True),
        # Fix(name="license_check", reghex="(?<= E8 ) . . . . . . . . .", patch=ret1, is_ref=True), # for SM 2058
    ]
    sm_macos_fixes = [
        Fix(name="server_validate", reghex="55 . . . . . . . . . . . . . . . . .", patch=ret1),
        Fix(name="license_notify", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", patch=ret),
        Fix(name="crash_reporter", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . .", patch=ret),
        Fix(name="blacklist_check", reghex="E8 . . . . . . . . . . . . . ."),
        Fix(name="license_recheck", reghex="E8 . . . . . . . . . . . . . . . . . ."),
        Fix(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . .", patch=ret281, is_ref=True),
        # Fix(name="license_check", reghex="(?<= E8 ) . . . . . . . . .", patch=ret1, is_ref=True), # for SM 2058
    ]
    sm_wind_fixes = [
        Fix(name="server_validate", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . . .", patch=ret1),
        Fix(name="license_notify", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . .", patch=ret),
        Fix(name="crash_reporter", reghex="41 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", patch=ret),
        Fix(name="blacklist_check", reghex="(?<= . . . . . . ) E8 . . . . . . . . . ."),
        Fix(name="license_recheck", reghex="(?<= . . . . . . ) E8 . . . . . . . . . . ."),
        Fix(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . .", patch=ret281, is_ref=True),
        # Fix(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . . . . .", patch=ret1, is_ref=True), # for SM 2058
    ]
    tagged_fixes = [
        ([b"x64", "SublimeText" ,            b"windows"], st_wind_fixes ),
        ([b"x64", "SublimeText" ,            b"osx"    ], st_macos_fixes),
        ([b"x64", "SublimeText" ,            b"linux"  ], st_linux_fixes),
        ([b"x64", "SublimeMerge",            b"windows"], sm_wind_fixes ),
        ([b"x64", "SublimeMerge",            b"osx"    ], sm_macos_fixes),
        ([b"x64", "SublimeMerge",            b"linux"  ], sm_linux_fixes),
    ]
    detects = [
        Fix(name="SublimeText", reghex=r"/updates/4/\w+_update_check\?version=\d+&platform=(?P<os>\w+)&arch=(?P<arch>\w+)"),
        Fix(name="SublimeMerge", reghex=r"/updates/\w+_update_check\?version=\d+&platform=(?P<os>\w+)&arch=(?P<arch>\w+)"),
    ]

    def Load(self, data):
        detected = set()
        for fix in self.detects:
            m = FindRegHex(fix, data)
            if m: detected |= set([ fix.name, *m.groups() ])
        print(f"[+] Detected tags: {detected}\n")
        for tags, fixes in self.tagged_fixes:
            if set(tags) == detected: return fixes
        exit("[!] Can not find fixes for target file")

def main():
    print(credits)
    target_file = input("Enter path to target file: ")
    PatchFile(target_file)

if __name__ == "__main__":
    main()
