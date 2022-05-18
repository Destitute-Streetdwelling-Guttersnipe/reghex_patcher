# tagged_fixes and detections are used by function FindFixes in reghex_patcher_full.py

import collections

zero4 = "00 " * 4
# for x64 CPU
nop = "90"
nop3 = "90 " * 3
nop4 = "90 " * 4
nop5 = "90 " * 5 # nop over E8 .{4} (call [dword])
ret = "C3" # ret
ret0 = "48 31 C0 C3" # xor rax, rax; ret
ret1 = "48 31 C0 48 FF C0 C3" # xor rax, rax; inc rax; ret
ret119 = "48 C7 C0 19 01 00 00 C3" # mov rax, 0x119; ret
ret0_rcx = "48 31 C0  48 8B 11  80 3A 2D  0F 95 C0  C3" # xor rax, rax; mov rdx, qword ptr [rcx]; cmp byte ptr [rdx], 0x2d; setne al; ret
ret0_rdi = "48 31 C0  48 8B 17  80 3A 2D  0F 95 C0  C3" # xor rax, rax; mov rdx, qword ptr [rdi]; cmp byte ptr [rax], 0x2d; setne al; ret
# comparison of detection methods:
# - detection of instructions in code section is the least stable among versions, platforms (arm64, amd64) and OS (Windows, Linux, macOS)
# - detection of constants in code section is more stable among versions and OS, but different among platforms (arm64, amd64)
# - detection of constants in data section is the most stable among versions, and more similar among platforms and OS, but difficult to create an effective patch 
# Notes on tuple Fix:
# - before making a regex search with fix.reghex, hex digits pairs are converted to hex-escape format and all spaces are removed
# - fix.name is splitted to set label for offsets of matching groups (from fix.reghex)
# - fix.ref is unused, any matching groups that has 4 bytes will be check if it's a reference to a string/function
# - fix.patch can be a string or a list of strings to patch each matching group
# - fix.look_behind is used to find the function that contains the matching groups
Fix = collections.namedtuple('Fix', 'name reghex patch ref arch look_behind', defaults=('', '', '', False, '', None)) # reghex is regex with hex bytes
st_wind_fixes = [
]
st_linux_fixes = [
]
st_macos_fixes = [
]
st_macos_fixes_arm64 = [
]
sm_wind_fixes = [
]
sm_linux_fixes = [
]
sm_macos_fixes = [
]
sm_macos_fixes_arm64 = [
]
st_blacklist_fixes = [
]
string_detections = [ # detect string in data & code sections
]
ref_detections = [
    # detection for number, string and function inside AMD64 instructions
    Fix(name="amd64", reghex=r"  (?<= C7 84 . .{4} | .{3} C7 44 . . | . C7 85 .{4} | 48 C7 05 .{4} ) . |" ## mov dword [r?+r?+?], ?; move [rip+?], ?
                          + r"(?<= . . 8D [81 87] | . 41 8D 8F | 41 8D 8C 24 | . . 81 [FC FF] ) . |" ## lea eax, [rdi+?]; lea ecx, [r1?+?]; lea ecx, [r12+?]; cmp edi, ?; cmp r?d, ?;
                          + r"(?<= . 41 BE | 41 81 C6 | . 81 [C1 C5 C7 F8 F9 FB FD FF] | 8D 9C 09 ) . |" ## mov e?, ?; mov r14d, ?; add r14d, ?; add e?, ?; cmp e?, ?; lea ebx, [rcx+rcx+?]
                          + r"(?<=  8A [80-84 86-8C 8E-94 96-97] | . [B8-BB BD-BF 3D] ) . |" ## mov ?l, byte ptr [r? + ?]; mov e?, ?; mov r?, ?; cmp eax, ?
                          + r"(?<= . . [E8 E9] | (?:[48 4C] 8D | 0F 10) [05 0D 15 1D 25 2D 35 3D] ) .", ## call ?; jmp ?; lea r?, [rip + ?]; movups xmm0, xmmword ptr [rip + ?]
        arch="amd64", look_behind=True),
    # detection for number, string and function inside ARM64 instructions
    Fix(name="arm64", reghex=r". (?=. . [10 94 97 14 17]) | (?<=[90 B0 D0 F0])  . (?=. . 91)", ## adr ? ; bl ? ; b ? ; adrp x?, ? ; add x?, x?, ?
        arch="arm64", look_behind=True),
]
st_delay_fixes = [ # extend the delay period
]
sm_delay_fixes = [ # extend the delay period
]
st_sm_remote_check_fixes = [ # data section fixes can be applied on all platforms
]
st_license_check_fixes = [ # data section fixes can be applied on all platforms
]
sm_license_check_fixes = [ # data section fixes can be applied on all platforms
]
tagged_fixes = [
    ([b"x64", "SublimeText" ,            b"windows"], string_detections + st_wind_fixes         + ref_detections ),
    ([b"x64", "SublimeText" ,            b"osx"    ], string_detections + st_macos_fixes        + ref_detections),
    ([        "SublimeText" ,  b"arm64", b"osx"    ], string_detections + st_macos_fixes_arm64  + ref_detections),
    ([b"x64", "SublimeText" ,            b"linux"  ], string_detections + st_linux_fixes        + ref_detections),
    ([b"x64", "SublimeMerge",            b"windows"], string_detections + sm_wind_fixes         + ref_detections ),
    ([b"x64", "SublimeMerge" ,           b"osx"    ], string_detections + sm_macos_fixes        + ref_detections),
    ([        "SublimeMerge" , b"arm64", b"osx"    ], string_detections + sm_macos_fixes_arm64  + ref_detections),
    ([b"x64", "SublimeMerge",            b"linux"  ], string_detections + sm_linux_fixes        + ref_detections),
    # ([        "SublimeText" ,                      ], st_blacklist_fixes + st_delay_fixes),
    # ([        "SublimeMerge",                      ], sm_blacklist_fixes + sm_delay_fixes),
    ([        "SublimeText" ,                      ], string_detections + ref_detections),
    ([        "SublimeMerge",                      ], string_detections + ref_detections),
    # ([        "SublimeText" ,                      ], st_sm_remote_check_fixes + st_license_check_fixes),
    # ([        "SublimeMerge",                      ], st_sm_remote_check_fixes + sm_license_check_fixes),
]
detections = [
    Fix(name="SublimeText", reghex=r"/updates/4/\w+_update_check\?version=\d+&platform=(\w+)&arch=(\w+)"), # arch: arm64, x64, x32
    Fix(name="SublimeMerge", reghex=r"/updates/\w+_update_check\?version=\d+&platform=(\w+)&arch=(\w+)"), # platform: windows, osx, linux
    # Fix(name="SublimeText", reghex=r"/updates/4/\w+_update_check\?version=\d+&platform=\w+&arch=\w+"),
    # Fix(name="SublimeMerge", reghex=r"/updates/\w+_update_check\?version=\d+&platform=\w+&arch=\w+"),
]

# sm: /updates/stable_update_check?version=2059&platform=linux&arch=x64
# sm: /updates/dev_update_check?version=2058&platform=linux&arch=arm64
# sm: /updates/dev_update_check?version=2058&platform=windows&arch=x64
# sm: /updates/dev_update_check?version=2058&platform=osx&arch=x64

# st: /updates/4/stable_update_check?version=4113&platform=osx&arch=arm64
# st: /updates/4/dev_update_check?version=4114&platform=osx&arch=x64
# st: /updates/4/dev_update_check?version=4114&platform=linux&arch=x64
# st: /updates/4/dev_update_check?version=4114&platform=windows&arch=x64

# /src/sublime_text/release_notes/
# /src/sublime_merge/release_notes/
# This will revert Sublime Text to an unregistered state
# This will revert Sublime Merge to an unregistered state
# Sublime Text build %s
# Sublime Merge build %s
# Sublime Text Build %s
# Sublime Merge Build %s
# You can purchase one from https://www.sublimetext.com/buy
# You can purchase a license at https://www.sublimemerge.com
# A new version of Sublime Merge is available, download now?

# uniform vec2 viewport;
# uniform vec2 position;
# uniform vec2 size;

# #if defined(ROUNDED) || defined(BORDERED)
# #ifdef SUPERSAMPLE
#     // 8x supersample rounded/bordered
#     // This is set up for 16x supersample in a grid, with half the samples commented out, giving us 8x
#     vec4 accumulator = vec4(0);
