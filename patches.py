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
Fix = collections.namedtuple('Fix', 'name reghex patch ref look_behind', defaults=('', '', '', False, None)) # reghex is regex with hex bytes
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
    Fix(name="ref1", reghex=r"  (?: C7 84 . .{4} | C7 44 . . | [41 48] [B8-BB BD-BF] |" ## mov dword ptr [r? + r? + ?], ? ; mov r?, ?
                          + r"[E8 E9] | 8A [80-84 86-8C 8E-94 96-97] | [B8-BB BD-BF] |" ## call ? ; jmp ? ; mov ?l, byte ptr [r? + ?] ; mov e?, ?
                          + r"    (?: [48 4C] 8D | 0F 10 ) [05 0D 15 1D 25 2D 35 3D] ) (.{4})" ## lea r?, [rip + ?] ; movups xmm0, xmmword ptr [rip + ?]
                          + r" | (.{3} [10 94 97 14 17]) | [90 B0 D0 F0] (.{3} 91)", ## bl ? ; b ? ; adrp x?, ? ; add x?, x?, ?
        ref=True, look_behind=True),
    # detection for number, string and function inside ARM64 instructions
    Fix(name="ref4", reghex=r"(?<= .{3} [90 B0 D0 F0] ) .{3} 91", ## adrp x?, ? ; add x?, x?, ?
        ref=True, look_behind=True),
]
st_delay_fixes = [ # extend the delay period
]
sm_delay_fixes = [ # extend the delay period
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
# Thanks for trying out Sublime Text.
# Thanks for trying out Sublime Merge.
# Thank you for purchasing Sublime Text!
# Thanks for purchasing, enjoy Sublime Merge!
# This will revert Sublime Text to an unregistered state
# This will revert Sublime Merge to an unregistered state
# That appears to be a Sublime Merge license key, instead of a Sublime Text key
# That appears to be a Sublime Text license key, instead of a Sublime Merge key
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
