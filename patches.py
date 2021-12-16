# tagged_fixes and detections are used by function FindFixes in reghex_patcher_full.py

import collections

zero4 = "00 " * 4
# for x64 CPU
nop = "90"
nop5 = "90 " * 5 # nop over E8 .{4} (call [dword])
ret = "C3" # ret
ret0 = "48 31 C0 C3" # xor rax, rax; ret
ret1 = "48 31 C0 48 FF C0 C3" # xor rax, rax; inc rax; ret
ret119 = "48 C7 C0 19 01 00 00 C3" # mov rax, 0x119; ret
Fix = collections.namedtuple('Fix', 'name reghex patch is_rva is_va is_pcr count', defaults=('', '', nop5, False, False, False, None)) # reghex is regex with hex bytes
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
st_delay_fixes = [ # extend the delay period
]
sm_delay_fixes = [ # extend the delay period
]
tagged_fixes = [
    ([b"x64", "SublimeText" ,            b"windows"], st_wind_fixes ),
    ([b"x64", "SublimeText" ,            b"osx"    ], st_macos_fixes),
    ([        "SublimeText" ,  b"arm64", b"osx"    ], st_macos_fixes_arm64),
    ([b"x64", "SublimeText" ,            b"linux"  ], st_linux_fixes),
    ([b"x64", "SublimeMerge",            b"windows"], sm_wind_fixes ),
    ([b"x64", "SublimeMerge" ,           b"osx"    ], sm_macos_fixes),
    ([        "SublimeMerge" , b"arm64", b"osx"    ], sm_macos_fixes_arm64),
    ([b"x64", "SublimeMerge",            b"linux"  ], sm_linux_fixes),
    ([        "SublimeText" ,                      ], st_blacklist_fixes + st_delay_fixes),
    ([        "SublimeMerge",                      ], st_blacklist_fixes + sm_delay_fixes),
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
