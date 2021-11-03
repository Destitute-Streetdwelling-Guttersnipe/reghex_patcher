credits = "[-] ---- RegHex Patcher by Destitute-Streetdwelling-Guttersnipe (Credits to leogx9r & rainbowpigeon for signatures and patching logic)"

import re
import patches as Fixes

def main():
    print(credits)
    target_file = input("Enter path to target file: ")
    PatchFile(target_file)

def PatchFile(input_file):
    with open(input_file, 'rb') as file:
        data = bytearray(file.read())
    Patch(data)
    with open(input_file, "wb") as file:
        file.write(data)
    print(f"[+] Patched file saved to {input_file}")

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

if __name__ == "__main__":
    main()
