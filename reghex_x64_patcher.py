credits = "[-] ---- Hex Patcher by Destitute-Streetdwelling-Guttersnipe (Credits to leogx9r & rainbowpigeon for signatures and patching logic)"

import re
import collections
import hashlib

class File():

    def __init__(self, filename):
        with open(filename, 'rb') as file:
            self.data = bytearray(file.read())

    def loadSigs(self):
        sigsData = Sigs.load(self.data)
        if not sigsData:
            raise ValueError("Could not find matching hash for input file")
        print("\n[+] Found signatures for {} version {} {}".format(sigsData['app'], sigsData['version'], sigsData['os']))
        return sigsData['sigs']

    def patch(self, sig):
        print("[+] Patching {}".format(sig.name))
        offset, new_bytes = Patch.searchIn(self.data, sig)
        print("[+] at {}: {} -> {}".format(hex(offset), HexBytes(self.data[offset:offset + len(new_bytes)]), HexBytes(new_bytes)))
        self.data[offset:offset + len(new_bytes)] = new_bytes

    def save(self, new_filename):
        with open(new_filename, "wb") as file:
            file.write(self.data)
        print("[+] Patched file written at {}".format(new_filename))

class Fix():
    CALL_LEN = 5  # E8 xx xx xx xx
    FIXES = {
        "nop": "90" * CALL_LEN, # nop for E8 xx xx xx xx
        "ret": "C3",  # ret
        "ret0": "48 31 C0 C3",  # xor rax, rax; ret
        "ret1": "48 31 C0 48 FF C0 C3",  # xor rax, rax; inc rax; ret
        "ret281": "48 C7 C0 19 01 00 00 C3",  # mov rax, 281; ret
    }

    @classmethod
    def new_bytes(cls, fix):
        assert fix in cls.FIXES
        return bytes.fromhex(cls.FIXES[fix])

class Patch:
    ANY_BYTE = b"."

    @classmethod
    def process_wildcards(cls, pattern):
        pattern = [re.escape(bytes.fromhex(byte)) if byte != "?" else cls.ANY_BYTE for byte in pattern.split(" ")]
        return b"".join(pattern)

    @classmethod
    def searchIn(self, data, sig):
        pattern = self.process_wildcards(sig.pattern)
        match = re.search(pattern, data, re.S)
        if not match:
            raise ValueError("Could not find pattern: {}".format(sig.pattern))
        offset = match.start() + sig.offset
        if sig.is_ref:
            offset = Ref.get_addr_from_call(offset, match.group(0)[sig.offset:])
        new_bytes = Fix.new_bytes(sig.fix)
        return offset, new_bytes

class Ref:
    CALL_LEN = 5  # E8 xx xx xx xx
    OPCODE_LEN = 1  # E8

    @classmethod
    def get_addr_from_call(cls, offset, call_bytes):
        addr_bytes = bytearray(call_bytes[cls.OPCODE_LEN:cls.CALL_LEN]) # assume RVA is at the end of the instruction
        rel_addr = int.from_bytes(addr_bytes, byteorder='little')
        addr = (offset + cls.CALL_LEN + rel_addr) & 0xFFFFFFFF
        print("[*] found RVA at {}: {} -> {}".format(hex(offset), hex(rel_addr), hex(addr)))
        return addr

def HexBytes(bytes):
    return ' '.join('{:02x}'.format(b) for b in bytes)

# NOTE: license_notify can use fix="ret" !
class Sigs:
    Sig = collections.namedtuple('Sig', 'name pattern is_ref offset fix', defaults=('', '', False, 0, 'nop'))
    st_linux_sigs = [
        Sig(name="license_check", pattern="E8 ? ? ? ? ? ? ? ? ? ? ? ? ?", is_ref=True, fix="ret0"),
        Sig(name="server_validate", pattern="55 ? ? ? ? ? ? ? ? ? ? ?", fix="ret1"),
        Sig(name="license_notify", pattern="41 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", fix="ret0"),
        Sig(name="crash_reporter", pattern="55 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", fix="ret"),
        Sig(name="invalidate1", pattern="E8 ? ? ? ? ? ? ? ? ? ? ? ?"),
        Sig(name="invalidate2", pattern="E8 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?"),
    ]
    st_macos_sigs = [
        Sig(name="license_check", pattern="E8 ? ? ? ? ? ? ? ? ? ? ? ? ?", is_ref=True, fix="ret0"),
        Sig(name="server_validate", pattern="55 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", fix="ret1"),
        Sig(name="license_notify", pattern="55 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", fix="ret0"),
        Sig(name="crash_reporter", pattern="55 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", fix="ret"),
        Sig(name="invalidate1", pattern="E8 ? ? ? ? ? ? ? ? ? ? ? ? ? ?"),
        Sig(name="invalidate2", pattern="E8 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?"),
    ]
    st_wind_sigs = [
        Sig(name="license_check", pattern="E8 ? ? ? ? ? ? ? ? ? ? ? ? ?", is_ref=True, fix="ret0"),
        Sig(name="server_validate", pattern="55 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", fix="ret1"),
        Sig(name="license_notify", pattern="55 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", fix="ret0"),
        Sig(name="crash_reporter", pattern="41 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", fix="ret"),
    ]
    st_wind_sigs_dev = [
        Sig(name="invalidate1", pattern="41 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", offset=6),
        Sig(name="invalidate2", pattern="41 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", offset=6),
    ]
    st_wind_sigs_stable = [
        Sig(name="invalidate1", pattern="41 ? ? ? ? ? ? ? ? ? ? ? ? ?", offset=6),
        Sig(name="invalidate2", pattern="E8 ? ? ? ? ? ? ? ? ? ? ? ? ?"),
    ]
    sm_linux_sigs = [
        Sig(name="server_validate", pattern="55 ? ? ? ? ? ? ? ? ? ? ?", fix="ret1"),
        Sig(name="license_notify", pattern="41 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", fix="ret0"),
        Sig(name="crash_reporter", pattern="55 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", fix="ret"),
        Sig(name="invalidate1", pattern="E8 ? ? ? ? ? ? ? ? ? ? ? ?"),
        Sig(name="invalidate2", pattern="E8 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?"),
    ]
    sm_linux_sigs_stable = [
        Sig(name="license_check", pattern="E8 ? ? ? ? ? ? ? ? ? ? ?", is_ref=True, fix="ret281"),
    ]
    sm_linux_sigs_dev = [
        Sig(name="license_check", pattern="E8 ? ? ? ? ? ? ? ? ?", is_ref=True, fix="ret1"),
    ]
    sm_macos_sigs = [
        Sig(name="server_validate", pattern="55 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", fix="ret1"),
        Sig(name="license_notify", pattern="55 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", fix="ret0"),
        Sig(name="crash_reporter", pattern="55 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", fix="ret"),
        Sig(name="invalidate1", pattern="E8 ? ? ? ? ? ? ? ? ? ? ? ? ? ?"),
        Sig(name="invalidate2", pattern="E8 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?"),
    ]
    sm_macos_sigs_stable = [
        Sig(name="license_check", pattern="E8 ? ? ? ? ? ? ? ? ? ? ?", is_ref=True, fix="ret281"),
    ]
    sm_macos_sigs_dev = [
        Sig(name="license_check", pattern="E8 ? ? ? ? ? ? ? ? ?", is_ref=True, fix="ret1"),
    ]
    sm_wind_sigs = [
        Sig(name="server_validate", pattern="55 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", fix="ret1"),
        Sig(name="license_notify", pattern="55 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", fix="ret0"),
        Sig(name="crash_reporter", pattern="41 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", fix="ret"),
        Sig(name="invalidate1", pattern="41 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", offset=6),
        Sig(name="invalidate2", pattern="41 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ?", offset=6),
    ]
    sm_wind_sigs_stable = [
        Sig(name="license_check", pattern="E8 ? ? ? ? ? ? ? ? ? ? ?", is_ref=True, fix="ret281"),
    ]
    sm_wind_sigs_dev = [
        Sig(name="license_check", pattern="E8 ? ? ? ? ? ? ? ? ? ? ? ? ? ?", is_ref=True, fix="ret1"),
    ]
    SIGS = dict(
        md5_4b9e87d1547a4fc9e47d6a6d8dc5e381 = dict(app="SublimeText", version="4113", os="windows", sigs=st_wind_sigs + st_wind_sigs_stable),
        md5_7be878dce68c856b4bf3045e18f08015 = dict(app="SublimeText", version="4113", os="macos", sigs=st_macos_sigs),
        md5_ff083966171185d01cb5f7f3721f1b95 = dict(app="SublimeText", version="4113", os="linux", sigs=st_linux_sigs),
        md5_2e3bbf78ed585983d04ad2c1cf123924 = dict(app="SublimeText", version="4114", os="windows", sigs=st_wind_sigs + st_wind_sigs_dev),
        md5_4f204e9d4e466d4a628f448d07009189 = dict(app="SublimeText", version="4114", os="macos", sigs=st_macos_sigs),
        md5_ca6ba5ac190184b20a02a0b0b380d83a = dict(app="SublimeText", version="4114", os="linux", sigs=st_linux_sigs),
        md5_d9baa87dba4655d3a4a3c878cecb6c5a = dict(app="SublimeMerge", version="2058", os="windows", sigs=sm_wind_sigs + sm_wind_sigs_dev),
        md5_46e2523e809c682e4445e201ba39c29a = dict(app="SublimeMerge", version="2058", os="macos", sigs=sm_macos_sigs + sm_macos_sigs_dev),
        md5_c3563e10088ad9e6f7407399c04fc877 = dict(app="SublimeMerge", version="2058", os="linux", sigs=sm_linux_sigs + sm_linux_sigs_dev),
        md5_29a9f8bbf4f4958cbf5e46922487681d = dict(app="SublimeMerge", version="2059", os="windows", sigs=sm_wind_sigs + sm_wind_sigs_stable),
        md5_c38ff301ddca0e2e8f84e76f6e25ca4b = dict(app="SublimeMerge", version="2059", os="macos", sigs=sm_macos_sigs + sm_macos_sigs_stable),
        md5_43e900a19926409edf6bd8ba8709c633 = dict(app="SublimeMerge", version="2059", os="linux", sigs=sm_linux_sigs + sm_linux_sigs_stable),
    )

    @classmethod
    def load(self, data):
        md5hash = hashlib.md5(data).hexdigest()
        return self.SIGS["md5_" + md5hash]

def main():
    print(credits)
    target_file = input("Enter path to target file: ")
    target = File(target_file)
    sigs = target.loadSigs()
    for sig in sigs:
        target.patch(sig)
    target.save(target_file)

if __name__ == "__main__":
    main()
