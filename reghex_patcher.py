credits = "[-] ---- RegHex Patcher by Destitute-Streetdwelling-Guttersnipe (Credits to leogx9r & rainbowpigeon for signatures and patching logic)"

import re

def PatchFile(input_file):
    with open(input_file, 'rb') as file:
        data = bytearray(file.read())
    Patch(data)
    with open(input_file, "wb") as file:
       file.write(data)
    print(f"[+] Patched file saved to {input_file}")

def FindRegHex(sig, data):
    matches = list(re.finditer(sig.reghex, data, re.DOTALL | re.VERBOSE))[:10] # only 10 matches
    if len(matches) == 0: return None
    print("[-] Found at {}: pattern {}".format(','.join([hex(m.start()) for m in matches]), sig.name))
    return matches[0] 

def Patch(data):
    for sig in Sigs().Load(data):
        match = FindRegHex(sig, data)
        if not match: exit("[!] Can not find pattern: {} '{}'".format(sig.name, sig.reghex))
        offset = match.start()
        if sig.is_ref: offset = RelativeOffset(offset, data)
        print("[+] Patch at {}: {}\n".format(hex(offset), sig.fix.hex(' ')))
        data[offset : offset + len(sig.fix)] = sig.fix

def RelativeOffset(offset, data):
    relative_address = int.from_bytes(data[offset : offset + 4], byteorder='little') # address size is 4 bytes
    return (offset + 4 + relative_address) & 0xFFFFFFFF

class Sigs:
    nop5 = "90" * 5 # nop over E8 . . . . (call [dword])
    ret = "C3" # ret
    ret0 = "48 31 C0 C3" # xor rax, rax; ret
    ret1 = "48 31 C0 48 FF C0 C3" # xor rax, rax; inc rax; ret
    ret281 = "48 C7 C0 19 01 00 00 C3" # mov rax, 281; ret

    class Sig:
        nop5 = "90" * 5 # nop over E8 . . . . (call [dword])
        def __init__(self, name, reghex, patch=nop5, is_ref=False): # reghex is regex with hex bytes
            self.name = name
            self.reghex = bytes(re.sub(r"\b([0-9a-fA-F]{2})\b", r"\\x\1", reghex), encoding='utf-8') # escape hex bytes
            self.is_ref = is_ref
            self.fix = bytes.fromhex(fix)
    # NOTE: license_notify was said to use fix=ret0 !
    st_linux_sigs = [
        Sig(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . . . .", fix=ret0, is_ref=True),
        Sig(name="server_validate", reghex="55 . . . . . . . . . . .", fix=ret1),
        Sig(name="license_notify", reghex="41 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", fix=ret),
        Sig(name="crash_reporter", reghex="55 . . . . . . . . . . . . . . . . . . . . . .", fix=ret),
        Sig(name="invalidate1", reghex="E8 . . . . . . . . . . . ."),
        Sig(name="invalidate2", reghex="E8 . . . . . . . . . . . . . . . ."),
    ]
    st_macos_sigs = [
        Sig(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . . . .", fix=ret0, is_ref=True),
        Sig(name="server_validate", reghex="55 . . . . . . . . . . . . . . . . .", fix=ret1),
        Sig(name="license_notify", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", fix=ret),
        Sig(name="crash_reporter", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . .", fix=ret),
        Sig(name="invalidate1", reghex="E8 . . . . . . . . . . . . . ."),
        Sig(name="invalidate2", reghex="E8 . . . . . . . . . . . . . . . . . ."),
    ]
    st_wind_sigs = [
        Sig(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . . . .", fix=ret0, is_ref=True),
        Sig(name="server_validate", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . . .", fix=ret1),
        Sig(name="license_notify", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", fix=ret),
        Sig(name="crash_reporter", reghex="41 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", fix=ret),
        Sig(name="invalidate1", reghex="(?<= . . . . . . ) E8 . . . . (48|49) . ."), # 48 for dev, 49 for stable
        Sig(name="invalidate2", reghex="(?<= . . . . . . ) E8 . . . . . . . . . (48|4C) . . ."), # 48 for dev, 4C for stable
    ]
    sm_linux_sigs = [
        Sig(name="server_validate", reghex="55 . . . . . . . . . . .", fix=ret1),
        Sig(name="license_notify", reghex="41 . . . . . . . . . . . . . . . . .", fix=ret),
        Sig(name="crash_reporter", reghex="55 . . . . . . . . . . . . . . . . . . . . . .", fix=ret),
        Sig(name="invalidate1", reghex="E8 . . . . . . . . . . . ."),
        Sig(name="invalidate2", reghex="E8 . . . . . . . . . . . . . . . ."),
    ]
    sm_linux_sigs_stable = [
        Sig(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . .", fix=ret281, is_ref=True),
    ]
    sm_linux_sigs_dev = [
        Sig(name="license_check", reghex="(?<= E8 ) . . . . . . . . .", fix=ret1, is_ref=True),
    ]
    sm_macos_sigs = [
        Sig(name="server_validate", reghex="55 . . . . . . . . . . . . . . . . .", fix=ret1),
        Sig(name="license_notify", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", fix=ret),
        Sig(name="crash_reporter", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . .", fix=ret),
        Sig(name="invalidate1", reghex="E8 . . . . . . . . . . . . . ."),
        Sig(name="invalidate2", reghex="E8 . . . . . . . . . . . . . . . . . ."),
    ]
    sm_macos_sigs_stable = [
        Sig(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . .", fix=ret281, is_ref=True),
    ]
    sm_macos_sigs_dev = [
        Sig(name="license_check", reghex="(?<= E8 ) . . . . . . . . .", fix=ret1, is_ref=True),
    ]
    sm_wind_sigs = [
        Sig(name="server_validate", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . . .", fix=ret1),
        Sig(name="license_notify", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . .", fix=ret),
        Sig(name="crash_reporter", reghex="41 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", fix=ret),
        Sig(name="invalidate1", reghex="(?<= . . . . . . ) E8 . . . . . . . . . ."),
        Sig(name="invalidate2", reghex="(?<= . . . . . . ) E8 . . . . . . . . . . ."),
    ]
    sm_wind_sigs_stable = [
        Sig(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . .", fix=ret281, is_ref=True),
    ]
    sm_wind_sigs_dev = [
        Sig(name="license_check", reghex="(?<= E8 ) . . . . . . . . . . . . . .", fix=ret1, is_ref=True),
    ]
    tagged_sigs = [
        (dict(arch=b"x64", app="SublimeText", channel=b"dev", os=b"windows"), st_wind_sigs),
        (dict(arch=b"x64", app="SublimeText", channel=b"dev", os=b"osx"), st_macos_sigs),
        (dict(arch=b"x64", app="SublimeText", channel=b"dev", os=b"linux"), st_linux_sigs),
        (dict(arch=b"x64", app="SublimeText", channel=b"stable", os=b"windows"), st_wind_sigs),
        (dict(arch=b"x64", app="SublimeText", channel=b"stable", os=b"osx"), st_macos_sigs),
        (dict(arch=b"x64", app="SublimeText", channel=b"stable", os=b"linux"), st_linux_sigs),
        (dict(arch=b"x64", app="SublimeMerge", channel=b"dev", os=b"windows"), sm_wind_sigs_dev + sm_wind_sigs),
        (dict(arch=b"x64", app="SublimeMerge", channel=b"dev", os=b"osx"), sm_macos_sigs_dev + sm_macos_sigs),
        (dict(arch=b"x64", app="SublimeMerge", channel=b"dev", os=b"linux"), sm_linux_sigs_dev + sm_linux_sigs),
        (dict(arch=b"x64", app="SublimeMerge", channel=b"stable", os=b"windows"), sm_wind_sigs_stable + sm_wind_sigs),
        (dict(arch=b"x64", app="SublimeMerge", channel=b"stable", os=b"osx"), sm_macos_sigs_stable + sm_macos_sigs),
        (dict(arch=b"x64", app="SublimeMerge", channel=b"stable", os=b"linux"), sm_linux_sigs_stable + sm_linux_sigs),
    ]
    detects = [
        Sig(name="SublimeText", reghex=r"/updates/4/(?P<channel>\w+)_update_check\?version=\d+&platform=(?P<os>\w+)&arch=(?P<arch>\w+)"),
        Sig(name="SublimeMerge", reghex=r"/updates/(?P<channel>\w+)_update_check\?version=\d+&platform=(?P<os>\w+)&arch=(?P<arch>\w+)"),
    ]

    def Load(self, data):
        for sig in self.detects:
            m = FindRegHex(sig, data)
            if m: detected = { "app": sig.name, **m.groupdict() }
        print(f"[+] Detected tags: {detected}\n")
        for tags, sigs in self.tagged_sigs:
            if tags == detected: return sigs
        exit("[!] Can not find sigs for target file")

def main():
    print(credits)
    target_file = input("Enter path to target file: ")
    PatchFile(target_file)

if __name__ == "__main__":
    main()
