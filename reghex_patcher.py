credits = "[-] ---- RegHex Patcher by Destitute-Streetdwelling-Guttersnipe (Credits to leogx9r & rainbowpigeon for signatures and patching logic)"

import re
import collections

class File:
    def __init__(self, filename):
        with open(filename, 'rb') as file:
            self.data = bytearray(file.read())

    def patch(self):
        for sig in Sigs().Load(self.data):
            Patcher().Patch(sig, self.data)        

    def save(self, new_filename):
        with open(new_filename, "wb") as file:
            file.write(self.data)
        print("[+] Patched file saved to {}".format(new_filename))

def FindRegHex(sig, data):
    pattern = re.sub(r"\b([0-9a-fA-F]{2})\b", r"\\x\1", sig.reghex) # escape hex bytes: E9 . . . . E8 . . . .
    matches = list(re.finditer(bytes(pattern, encoding='utf-8'), data, re.DOTALL | re.VERBOSE))[:10] # only 10 matches
    if len(matches) == 1: print("[-] Found at 0x{:x}: pattern {}".format(matches[0].start(), sig.name))
    if len(matches) > 1: print("[!] Found pattern {}: at {}".format(sig.name, ','.join([hex(m.start()) for m in matches])))
    return matches[0] if len(matches) > 0 else None

class Patcher:
    def Patch(self, sig, data):
        match = FindRegHex(sig, data)
        if not match: exit("[!] Can not find pattern: {} '{}'".format(sig.name, sig.reghex))
        offset = match.start()
        if sig.is_ref:
            offset = self.RelativeOffset(offset, data)
        new_bytes = self.Fix2newBytes(sig.fix, data[offset])
        print("[+] Patch at 0x{:x}: {}\n".format(offset, new_bytes.hex(' ')))
        data[offset : offset + len(new_bytes)] = new_bytes

    def RelativeOffset(self, offset, data):
        next_offset = offset + self.InstructionLength(data[offset])
        relative_address = int.from_bytes(data[next_offset - 4 : next_offset], byteorder='little') # assume the address is at the end of the instruction
        return (next_offset + relative_address) & 0xFFFFFFFF

    FIXES = {
        "nop": "90", # nop
        "ret": "C3",  # ret
        "ret0": "48 31 C0 C3",  # xor rax, rax; ret
        "ret1": "48 31 C0 48 FF C0 C3",  # xor rax, rax; inc rax; ret
        "ret281": "48 C7 C0 19 01 00 00 C3",  # mov rax, 281; ret
    }
    # FIXES.update((k, bytes.fromhex(v)) for k, v in FIXES.items())

    def Fix2newBytes(self, fix, opcode):
        if not fix in self.FIXES: exit("[!] Can not find fix: {}".format(fix))
        length = self.InstructionLength(opcode) if fix == "nop" else 1
        return bytes.fromhex(self.FIXES[fix]) * length

    INSTRUCTION_LENGTHS = {
        "E8": 5, # call [dword]
    }

    def InstructionLength(self, opcode):
        length = self.INSTRUCTION_LENGTHS["{:X}".format(opcode)]
        if not length: exit("[!] Can not find instruction: {:X}".format(opcode))
        return length

# NOTE: license_notify was said to use fix="ret0" !
class Sigs:
    Sig = collections.namedtuple('Sig', 'name reghex is_ref fix', defaults=('', '', False, 'nop')) # reghex is regex with hex bytes
    st_linux_sigs = [
        Sig(name="license_check", reghex="E8 . . . . . . . . . . . . .", is_ref=True, fix="ret0"),
        Sig(name="server_validate", reghex="55 . . . . . . . . . . .", fix="ret1"),
        Sig(name="license_notify", reghex="41 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", fix="ret"),
        Sig(name="crash_reporter", reghex="55 . . . . . . . . . . . . . . . . . . . . . .", fix="ret"),
        Sig(name="invalidate1", reghex="E8 . . . . . . . . . . . ."),
        Sig(name="invalidate2", reghex="E8 . . . . . . . . . . . . . . . ."),
    ]
    st_macos_sigs = [
        Sig(name="license_check", reghex="E8 . . . . . . . . . . . . .", is_ref=True, fix="ret0"),
        Sig(name="server_validate", reghex="55 . . . . . . . . . . . . . . . . .", fix="ret1"),
        Sig(name="license_notify", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", fix="ret"),
        Sig(name="crash_reporter", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . .", fix="ret"),
        Sig(name="invalidate1", reghex="E8 . . . . . . . . . . . . . ."),
        Sig(name="invalidate2", reghex="E8 . . . . . . . . . . . . . . . . . ."),
    ]
    st_wind_sigs = [
        Sig(name="license_check", reghex="E8 . . . . . . . . . . . . .", is_ref=True, fix="ret0"),
        Sig(name="server_validate", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . . .", fix="ret1"),
        Sig(name="license_notify", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", fix="ret"),
        Sig(name="crash_reporter", reghex="41 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", fix="ret"),
        Sig(name="invalidate1", reghex="(?<= . . . . . . ) E8 . . . . (48|49) . ."), # 48 for dev, 49 for stable
        Sig(name="invalidate2", reghex="(?<= . . . . . . ) E8 . . . . . . . . . (48|4C) . . ."), # 48 for dev, 4C for stable
    ]
    sm_linux_sigs = [
        Sig(name="server_validate", reghex="55 . . . . . . . . . . .", fix="ret1"),
        Sig(name="license_notify", reghex="41 . . . . . . . . . . . . . . . . .", fix="ret"),
        Sig(name="crash_reporter", reghex="55 . . . . . . . . . . . . . . . . . . . . . .", fix="ret"),
        Sig(name="invalidate1", reghex="E8 . . . . . . . . . . . ."),
        Sig(name="invalidate2", reghex="E8 . . . . . . . . . . . . . . . ."),
    ]
    sm_linux_sigs_stable = [
        Sig(name="license_check", reghex="E8 . . . . . . . . . . .", is_ref=True, fix="ret281"),
    ]
    sm_linux_sigs_dev = [
        Sig(name="license_check", reghex="E8 . . . . . . . . .", is_ref=True, fix="ret1"),
    ]
    sm_macos_sigs = [
        Sig(name="server_validate", reghex="55 . . . . . . . . . . . . . . . . .", fix="ret1"),
        Sig(name="license_notify", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", fix="ret"),
        Sig(name="crash_reporter", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . .", fix="ret"),
        Sig(name="invalidate1", reghex="E8 . . . . . . . . . . . . . ."),
        Sig(name="invalidate2", reghex="E8 . . . . . . . . . . . . . . . . . ."),
    ]
    sm_macos_sigs_stable = [
        Sig(name="license_check", reghex="E8 . . . . . . . . . . .", is_ref=True, fix="ret281"),
    ]
    sm_macos_sigs_dev = [
        Sig(name="license_check", reghex="E8 . . . . . . . . .", is_ref=True, fix="ret1"),
    ]
    sm_wind_sigs = [
        Sig(name="server_validate", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . . . .", fix="ret1"),
        Sig(name="license_notify", reghex="55 . . . . . . . . . . . . . . . . . . . . . . . .", fix="ret"),
        Sig(name="crash_reporter", reghex="41 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", fix="ret"),
        Sig(name="invalidate1", reghex="(?<= . . . . . . ) E8 . . . . . . . . . ."),
        Sig(name="invalidate2", reghex="(?<= . . . . . . ) E8 . . . . . . . . . . ."),
    ]
    sm_wind_sigs_stable = [
        Sig(name="license_check", reghex="E8 . . . . . . . . . . .", is_ref=True, fix="ret281"),
    ]
    sm_wind_sigs_dev = [
        Sig(name="license_check", reghex="E8 . . . . . . . . . . . . . .", is_ref=True, fix="ret1"),
    ]
    tagged_sigs = [
        dict(tags=dict(app="SublimeText", channel="dev", os="windows"), sigs=st_wind_sigs),
        dict(tags=dict(app="SublimeText", channel="dev", os="macos"), sigs=st_macos_sigs),
        dict(tags=dict(app="SublimeText", channel="dev", os="linux"), sigs=st_linux_sigs),
        dict(tags=dict(app="SublimeText", channel="stable", os="windows"), sigs=st_wind_sigs),
        dict(tags=dict(app="SublimeText", channel="stable", os="macos"), sigs=st_macos_sigs),
        dict(tags=dict(app="SublimeText", channel="stable", os="linux"), sigs=st_linux_sigs),
        dict(tags=dict(app="SublimeMerge", channel="dev", os="windows"), sigs=sm_wind_sigs_dev + sm_wind_sigs),
        dict(tags=dict(app="SublimeMerge", channel="dev", os="macos"), sigs=sm_macos_sigs_dev + sm_macos_sigs),
        dict(tags=dict(app="SublimeMerge", channel="dev", os="linux"), sigs=sm_linux_sigs_dev + sm_linux_sigs),
        dict(tags=dict(app="SublimeMerge", channel="stable", os="windows"), sigs=sm_wind_sigs_stable + sm_wind_sigs),
        dict(tags=dict(app="SublimeMerge", channel="stable", os="macos"), sigs=sm_macos_sigs_stable + sm_macos_sigs),
        dict(tags=dict(app="SublimeMerge", channel="stable", os="linux"), sigs=sm_linux_sigs_stable + sm_linux_sigs),
    ]
    detects = dict(
        app=[
            Sig(name="SublimeText", reghex=r"Thank\ you\ for\ purchasing\ Sublime\ Text!"), # Thanks for trying out Sublime Text.
            Sig(name="SublimeMerge", reghex=r"Thanks\ for\ purchasing,\ enjoy\ Sublime\ Merge!"), # Thanks for trying out Sublime Merge.
        ],
        channel=[
            Sig(name="dev", reghex=r"/dev_update_check"),
            Sig(name="stable", reghex=r"/stable_update_check"),
        ],
        os=[
            Sig(name="windows", reghex="^ 4D 5A"), # "MZ"
            Sig(name="linux", reghex="^ 7F 45 4C 46"), # "\x7F" "ELF"
            Sig(name="macos", reghex="^ CA FE BA BE"),
        ],
    )

    def Load(self, data):
        detected = {}
        for tag, sigs in self.detects.items():
            detected[tag] = next((sig.name for sig in sigs if FindRegHex(sig, data)), None)
        print("[+] Detected tags: {}\n".format(detected))
        for item in self.tagged_sigs:
            if item['tags'] == detected: return item['sigs']
        exit("[!] Can not find sigs for target file")

def main():
    print(credits)
    target_file = input("Enter path to target file: ")
    target = File(target_file)
    target.patch()
    target.save(target_file)

if __name__ == "__main__":
    main()
