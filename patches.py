# tagged_fixes and detections are used by function FindFixes in reghex_patcher_full.py

import collections

# for x64 CPU
nop5 = "90 " * 5 # nop over E8 .{4} (call [dword])
ret = "C3" # ret
ret0 = "48 31 C0 C3" # xor rax, rax; ret
ret1 = "48 31 C0 48 FF C0 C3" # xor rax, rax; inc rax; ret
ret119 = "48 C7 C0 19 01 00 00 C3" # mov rax, 0x119; ret
# for ARM64 CPU
_nop = "1F 20 03 D5" # nop
_ret = "C0 03 5F D6" # ret
_ret0 = "E0 03 1F AA C0 03 5F D6" # mov x0, xzr; ret

Fix = collections.namedtuple('Fix', 'name reghex patch is_ref', defaults=('', '', nop5, False)) # reghex is regex with hex bytes
# NOTE: server_validate can also be patched with ret
st_wind_fixes = [
    Fix(name="rsa_key_function", reghex="41 57  41 56  56  57  55  53  B8 28 21 00 00", patch=ret1), # allows any key in right format to work
    # Fix(name="license_check", reghex="(?<= 4C 8D 4D .  E8 ) .{4} 48 8B 8B .{4} 85 C0", patch=ret0, is_ref=True), # until build 4116
    Fix(name="license_check", reghex="(?<= 4C 8D 4D .  E8 ) .{4}  49 8B 8E .{4}  85 C0", patch=ret0, is_ref=True),
    Fix(name="license_check", reghex="(?<= 31 D2  45 31 C0  45 31 C9  E8 ) .{4}  85 C0  75 (15|0D)", patch=ret0, is_ref=True), # 15 for blacklist_check, 0D for license_recheck
    Fix(name="license_check", reghex="(?<= 48 8D 4D 40  E8 ) .{4}  48 8B 4E .  85 C0", patch=ret0, is_ref=True), # at startup?
    Fix(name="license_check", reghex="(?<= 48 89 F9  E8 ) .{4}  48 8B 4E .  85 C0", patch=ret0, is_ref=True), # at startup?
    Fix(name="server_validate", reghex="55  56  57  48 83 EC 30  48 8D 6C 24 .  48 C7 45 . .{4}  89 D6  48 89 CF  6A 28", patch=ret1),
    Fix(name="license_notify", reghex="55  56  57  48 81 EC .{4}  48 8D AC 24 .{4}  0F 29 B5 .{4}  48 C7 85 .{4} .{4}  48 89 CF", patch=ret),
    Fix(name="crash_reporter", reghex="41 57  41 56  41 55  41 54  56  57  55  53  B8 .{4}  E8 .{4}  48 29 C4  8A 84 24 .{4}", patch=ret),
    Fix(name="blacklist_check", reghex="(?<= 48 8D 0D .{4}  41 B8 88 13 00 00 )  E8 .{4}  (48|49) 8B 96"), # 48 for dev, 49 for stable
    Fix(name="license_recheck", reghex="(?<= 48 8D 0D .{4}  41 B8 98 3A 00 00 )  E8 .{4} E8 .{4}  (48|4C) 89 F1  E8 .{4}"), # 48 for dev, 4C for stable
    Fix(name="unregister_delay_after_blacklist_check", reghex="(?<= 48 8D 0D .{4}  4C 89 F2  41 B8 ) 00 53 07 00  E8 .{4}  48 8D 8D .{4}  E8 .{4}", patch="7F 7F 7F 7F"), # 41 B8 00 53 07 00 : mov r8d, 0x057E40 # 480 seconds
    Fix(name="unregister_delay_after_license_recheck", reghex="(?<= 48 8D 0D .{4}  48 89 F2  41 B8 ) 40 7E 05 00  48 83 C4 30  5E  E9 .{4}", patch="7F 7F 7F 7F"), # 41 B8 40 7E 05 00 : mov r8d, 0x057E40 # 360 seconds
]
st_linux_fixes = [
    Fix(name="license_check", reghex="(?<= 48 8D 4C 24 .  E8 ) .{4}  49 8B BF .{4}  85 C0", patch=ret0, is_ref=True),
    Fix(name="license_check", reghex="(?<= 48 89 E7  E8 ) .{4}  49 8B 7F .  85 C0", patch=ret0, is_ref=True), # 2 times at startup?
    Fix(name="license_check", reghex="(?<= 31 F6  31 D2  31 C9  45 31 C0  45 31 C9  E8 ) .{4}  85 C0  75 (12|09)", patch=ret0, is_ref=True), # 12 for blacklist_check, 09 for license_recheck
    Fix(name="server_validate", reghex="55  41 56  53  41 89 F6  48 89 FD  6A 28", patch=ret1),
    Fix(name="license_notify", reghex="41 56  53 48  81 EC .{4} 48 89 FB  BF .{4}  E8 .{4}  4C 8D B4 24 .{4}", patch=ret),
    Fix(name="crash_reporter", reghex="55  41 57  41 56  41 55  41 54  53  48 81 EC .{4}  41 89 D4  48 89 FD", patch=ret),
    # Fix(name="blacklist_check", reghex="(?<= BA .{4} ) E8 .{4} 48 89 5C 24 . 48 8B B3 .{4} BF"), # until 4120
    Fix(name="blacklist_check", reghex="(?<= BF .{4}  BA 88 13 00 00 )  E8 .{4}  49 8B B7 .{4}  BF"), # BA 88 13 00 00 : mov edx, 0x1388 # 5 seconds
    Fix(name="license_recheck", reghex="(?<= BF .{4}  BA 98 3A 00 00 )  E8 .{4}  BF .{4}  E8 .{4}  83 25"), # BA 98 3A 00 00 : mov edx, 0x3A98 # 15 seconds
    Fix(name="unregister_delay_after_blacklist_check", reghex="(?<= BF .{4}  4C 89 F6  BA ) 00 53 07 00  E8 .{4}  48 8D 7C 24 .  E8 .{4}", patch="7F 7F 7F 7F"), # BA 00 53 07 00 : mov edx, 0x057E40 # 480 seconds
    Fix(name="unregister_delay_after_license_recheck", reghex="(?<= BF .{4}  48 89 DE  BA ) 40 7E 05 00  5B  E9 .{4}", patch="7F 7F 7F 7F"), # BA 40 7E 05 00 : mov edx, 0x057E40 # 360 seconds
]
st_macos_fixes = [
    Fix(name="license_check", reghex="(?<= 48 8D 4D .  E8 ) .{4} 49 8B BF .{4}  85 C0", patch=ret0, is_ref=True),
    Fix(name="license_check", reghex="(?<= 48 8D 7D .  E8 ) .{4} 49 8B 7F .  85 C0", patch=ret0, is_ref=True), # at startup?
    Fix(name="license_check", reghex="(?<= 4C 89 E7  E8 ) .{4} 49 8B 7F .  85 C0", patch=ret0, is_ref=True), # at startup?
    Fix(name="license_check", reghex="(?<= 31 F6  31 D2  31 C9  45 31 C0  45 31 C9  E8 ) .{4}  85 C0  75 (14|0D)", patch=ret0, is_ref=True), # 14 for blacklist_check, 0D for license_recheck
    Fix(name="server_validate", reghex="55  48 89 E5  41 57  41 56  53  50  41 89 F6  49 89 FF  6A 20", patch=ret1),
    Fix(name="license_notify", reghex="55  48 89 E5  53  48 81 EC .{4}  48 89 FB  48 8B 05 .{4}  48 8B 00  48 89 45 F0  48 8D 3D .{4}", patch=ret),
    Fix(name="crash_reporter", reghex="55  48 89 E5  41 57  41 56  41 55  41 54  53 48  81 EC .{4} 41 89 CE  49 89 F7", patch=ret),
    Fix(name="blacklist_check", reghex="(?<= 48 8D 3D .{4}  BA 88 13 00 00 )  E8 .{4}  48 89 9D .{4}  48 8B B3"), # BA 88 13 00 00 : mov edx, 0x1388 # 5 seconds
    Fix(name="license_recheck", reghex="(?<= 48 8D 3D .{4}  BA 98 3A 00 00 )  E8 .{4}  48 8D 3D .{4}  E8 .{4}  83 25"), # BA 98 3A 00 00 : mov edx, 0x3A98 # 15 seconds
    Fix(name="unregister_delay_after_blacklist_check", reghex="(?<= 48 8D 3D .{4}  4C 89 F6  BA ) 00 53 07 00  E8 .{4} 48 8D 7D .  E8 .{4}", patch="7F 7F 7F 7F"), # BA 00 53 07 00 : mov edx, 0x057E40 # 480 seconds
    Fix(name="unregister_delay_after_license_recheck", reghex="(?<= 48 8D 3D .{4}  48 89 DE  BA ) 40 7E 05 00  48 83 C4 08  5B  5D  E9 .{4}", patch="7F 7F 7F 7F"), # BA 40 7E 05 00 : mov edx, 0x057E40 # 360 seconds
]
st_macos_fixes_arm64 = [
    Fix(name="license_check", reghex="(?<= 08 00 80 52  .{3} 14 ) E6 03 1E AA  .{3} 94  FE 03 06 AA", patch=_ret0),
    Fix(name="server_validate", reghex="F6 57 BD A9  F4 4F 01 A9  FD 7B 02 A9  FD 83 00 91  .{3} 94  .{3} 94  F3 03 00 AA  .{3} 94  74 1A 00 B9", patch=_ret),
    Fix(name="license_notify", reghex="FC 6F BD A9  F4 4F 01 A9  FD 7B 02 A9  FD 83 00 91  FF 43 0C D1  F3 03 00 AA", patch=_ret),
    Fix(name="crash_reporter", reghex="FC 6F BC A9  F6 57 01 A9  F4 4F 02 A9  FD 7B 03 A9  FD C3 00 91  FF 03 0F D1", patch=_ret),
    Fix(name="blacklist_check", reghex="(?<= 61 46 41 F9  . . 00 10  1F 20 03 D5  02 71 82 52 )  .{3} 94  61 46 41 F9  . . 00 10", patch=_nop), # 02 71 82 52 : movz w2, #0x1388 # 16 bits are stored as 3 MSB bits, 8 bits, 5 LSB bits
    Fix(name="license_recheck", reghex="(?<= 61 46 41 F9  . . 00 10  1F 20 03 D5  02 53 87 52 )  .{3} 94  .{3} D0  F7 A2 07 91", patch=_nop), # 02 53 87 52 : movz w2, #0x3A98
    # Fix(name="blacklist_check", reghex="(?<= . . 00 10  1F 20 03 D5  02 71 82 52 )  .{3} 94  61 46 41 F9  . . 00 10  1F 20 03 D5  02 53 87 52", patch=_nop),
    # Fix(name="license_recheck", reghex="(?<= . . 00 10  1F 20 03 D5  02 53 87 52 )  .{3} 94  . 2F 00 .  F7 . . 91  E0 42 . 91  E0 6F 00 F9", patch=_nop),
    Fix(name="unregister_delay_after_blacklist_check", reghex="(?<= 1F 20 03 D5  E1 03 13 AA  02 60 8A 52 )  E2 00 A0 72  .{3} 94", patch="E2 EF AF 72"), # 02 60 8A 52  E2 00 A0 72 : movz w2, #0x5300 ; movk w2, #0x7, lsl #16
    Fix(name="unregister_delay_after_license_recheck", reghex="(?<= 1F 20 03 D5  E1 03 13 AA  02 C8 8F 52 )  A2 00 A0 72  FD 7B 41 A9  .{3} 14", patch="E2 EF AF 72"), # 02 C8 8F 52  A2 00 A0 72 : movz w2, #0x7E40 ; movk w2, #0x5, lsl #16
]
sm_wind_fixes = [
    # Fix(name="license_check", reghex="(?<= E8 ) .{4} 49 8B 8E .{4} 83 F8 01", patch=ret1, is_ref=True), # only build 2058
    Fix(name="license_check", reghex="(?<= 48 8D 4D .  E8 ) .{4}  49 8B 8E .{4}  3D 19 01 00 00", patch=ret119, is_ref=True), # 3D 19 01 00 00 : cmp eax, 0x119
    Fix(name="license_check", reghex="(?<= 4C 8D 4D .  E8 ) .{4}  48 8B 4E .  3D 19 01 00 00", patch=ret119, is_ref=True), # at startup?
    Fix(name="license_check", reghex="(?<= 4C 8D 4D .  48 89 F9  E8 ) .{4}  48 8B 4E .  3D 19 01 00 00", patch=ret119, is_ref=True), # at startup?
    Fix(name="license_check", reghex="(?<= 31 D2  45 31 C0  45 31 C9  E8 ) .{4}  3D 19 01 00 00  75 (15|0D)", patch=ret119, is_ref=True), # 15 for blacklist_check, 0D for license_recheck
    Fix(name="server_validate", reghex="55  56  57  48 83 EC 30  48 8D 6C 24 .  48 C7 45 . .{4}  89 D6  48 89 CF  6A 28", patch=ret1),
    Fix(name="license_notify", reghex="55  56  57  48 81 EC .{4}  48 8D AC 24 .{4}  0F 29 B5 .{4}", patch=ret),
    Fix(name="crash_reporter", reghex="41 57  41 56  41 55  41 54  56  57  55  53  B8 .{4}  E8 .{4}  48 29 C4  8A 84 24 .{4}", patch=ret),
    Fix(name="blacklist_check", reghex="(?<= 48 8D 0D .{4}  41 B8 88 13 00 00 )  E8 .{4}  48 8B 96 .{4}"),
    Fix(name="license_recheck", reghex="(?<= 48 8D 0D .{4}  41 B8 98 3A 00 00 )  E8 .{4}  E8 .{4}  B9 .{4}"),
]
sm_linux_fixes = [
    # Fix(name="license_check", reghex="(?<= E8 ) .{4} 83 F8 01 75 12", patch=ret1, is_ref=True), # only build 2058
    Fix(name="license_check", reghex="(?<= 48 8D 7C 24 .  E8 ) .{4}  49 8B BF .{4}  3D 19 01 00 00", patch=ret119, is_ref=True), # 3D 19 01 00 00 : cmp eax, 0x119
    Fix(name="license_check", reghex="(?<= 48 8D 4C 24 .  E8 ) .{4}  49 8B 7F .  3D 19 01 00 00", patch=ret119, is_ref=True), # 2 times at startup?
    Fix(name="license_check", reghex="(?<= 31 F6  31 D2  31 C9  45 31 C0  E8 ) .{4}  3D 19 01 00 00  75 (12|09)", patch=ret119, is_ref=True), # 12 for blacklist_check, 09 for license_recheck
    Fix(name="server_validate", reghex="55  41 56  53  41 89  F6 48  89 FD  6A 28", patch=ret1),
    Fix(name="license_notify", reghex="41 56 53  48 81 EC .{4} 48 89 FB BF .{4}", patch=ret),
    Fix(name="crash_reporter", reghex="55  41 57  41 56  41 55  41 54  53  48 81 EC .{4}  41 89 D4  48 89 FD", patch=ret),
    Fix(name="blacklist_check", reghex="(?<= BF .{4}  BA 88 13 00 00 )  E8 .{4}  48 89 5C 24 .  48 8B B3 .{4}"),
    Fix(name="license_recheck", reghex="(?<= BF .{4}  BA 98 3A 00 00 )  E8 .{4}  BF .{4}  E8 .{4}  83 25"),
]
sm_macos_fixes = [
    # Fix(name="license_check", reghex="(?<= E8 ) .{4} 83 F8 01 75 14", patch=ret1, is_ref=True), # only build 2058
    Fix(name="license_check", reghex="(?<= 48 8D BD .{4}  E8 ) .{4}  49 8B BF .{4}  3D 19 01 00 00", patch=ret119, is_ref=True), # 3D 19 01 00 00 : cmp eax, 0x119
    Fix(name="license_check", reghex="(?<= 48 8D 4D .  E8 ) .{4}  49 8B 7F .  3D 19 01 00 00", patch=ret119, is_ref=True), # at startup?
    Fix(name="license_check", reghex="(?<= 48 89 DF  E8 ) .{4}  49 8B 7F .  3D 19 01 00 00", patch=ret119, is_ref=True), # at startup?
    Fix(name="license_check", reghex="(?<= 31 F6  31 D2  31 C9  45 31 C0  E8 ) .{4}  3D 19 01 00 00  75 (14|0D)", patch=ret119, is_ref=True), # 14 for blacklist_check, 0D for license_recheck
    Fix(name="server_validate", reghex="55  48 89 E5  41 57  41 56  53  50  41 89 F6  49 89 FF  6A 20", patch=ret1),
    Fix(name="license_notify", reghex="55  48 89 E5  53  48 81 EC .{4}  48 89 FB  48 8B 05 .{4}  48 8B 00  48 89 45 F0  48 8D 3D .{4}", patch=ret),
    Fix(name="crash_reporter", reghex="55  48 89 E5  41 57  41 56  41 55  41 54  53  48 81 EC .{4}  41 89 CE  49 89 F7", patch=ret),
    Fix(name="blacklist_check", reghex="(?<= 48 8D 3D .{4}  BA 88 13 00 00 )  E8 .{4}  48 89 9D .{4}  48 8B B3"),
    Fix(name="license_recheck", reghex="(?<= 48 8D 3D .{4}  BA 98 3A 00 00 )  E8 .{4}  48 8D 3D .{4}  E8 .{4}  83 25"),
]
sm_macos_fixes_arm64 = [
    Fix(name="license_check", reghex="F8 5F BC A9  F6 57 01 A9  F4 4F 02 A9  FD 7B 03 A9  FD C3 00 91  FF 03 08 D1  (F6 03 03 AA)?  .{3} 94", patch=_ret0),
    Fix(name="server_validate", reghex="F6 57 BD A9  F4 4F 01 A9  FD 7B 02 A9  FD 83 00 91  .{3} 94  .{3} 94  F3 03 00 AA  .{3} 94  74 1A 00 B9", patch=_ret),
    Fix(name="license_notify", reghex="FC 6F BD A9  F4 4F 01 A9  FD 7B 02 A9  FD 83 00 91  FF 43 0C D1  F3 03 00 AA", patch=_ret),
    Fix(name="crash_reporter", reghex="FC 6F BC A9  F6 57 01 A9  F4 4F 02 A9  FD 7B 03 A9  FD C3 00 91  FF 03 0F D1", patch=_ret),
    Fix(name="blacklist_check", reghex=".{3} 94  61 62 41 F9  . . 00 10  1F 20 03 D5  02 53 87 52", patch=_nop),
    Fix(name="license_recheck", reghex=".{3} 94  . 32 00 .  5A . . 91  40 . . 91  E0 37 00 F9", patch=_nop),
]
st_blacklist_fixes = [
    Fix(name="blacklisted_license_0D9497", reghex="97 94 0D 00", patch="00 00 00 00"), # EA7E-890007 TwitterInc
    Fix(name="blacklisted_license_0C4DFB", reghex="FB 4D 0C 00", patch="00 00 00 00"), # EA7E-806395 MinBan
    Fix(name="blacklisted_license_0C4F27", reghex="27 4F 0C 00", patch="00 00 00 00"), # EA7E-806695 Yandex, LLC
    Fix(name="blacklisted_license_0C5054", reghex="54 50 0C 00", patch="00 00 00 00"), # EA7E-806996 riku
    Fix(name="blacklisted_license_0C6331", reghex="31 63 0C 00", patch="00 00 00 00"), # EA7E-811825 ZYNGA INC.
    Fix(name="blacklisted_license_0C7F21", reghex="21 7F 0C 00", patch="00 00 00 00"), # EA7E-818977 Molex, Inc.
    Fix(name="blacklisted_license_0C82E3", reghex="E3 82 0C 00", patch="00 00 00 00"), # EA7E-819939 Dennis Wright Jr
    Fix(name="blacklisted_license_0C8889", reghex="89 88 0C 00", patch="00 00 00 00"), # EA7E-821385 Michael Barnes
    Fix(name="blacklisted_license_0D05B0", reghex="B0 05 0D 00", patch="00 00 00 00"), # EA7E-853424 Esri, Inc
    Fix(name="blacklisted_license_0D0E35", reghex="35 0E 0D 00", patch="00 00 00 00"), # EA7E-855605 Andrew Weber
    Fix(name="blacklisted_license_0D100D", reghex="0D 10 0D 00", patch="00 00 00 00"), # EA7E-856077 Derek Soulliere
    Fix(name="blacklisted_license_0D371B", reghex="1B 37 0D 00", patch="00 00 00 00"), # EA7E-866075 Nicolas Hennion
    Fix(name="blacklisted_license_0D67E3", reghex="E3 67 0D 00", patch="00 00 00 00"), # EA7E-878563 Anthony Sansone
    Fix(name="blacklisted_license_0DB44F", reghex="4F B4 0D 00", patch="00 00 00 00"), # EA7E-898127 Dylan Tittel
    Fix(name="blacklisted_license_0DC5AF", reghex="AF C5 0D 00", patch="00 00 00 00"), # EA7E-902575 andress
    Fix(name="blacklisted_license_0DDEE2", reghex="E2 DE 0D 00", patch="00 00 00 00"), # EA7E-909026 Affinity Computer Technology
    Fix(name="blacklisted_license_0E1972", reghex="72 19 0E 00", patch="00 00 00 00"), # EA7E-924018 Morin
    Fix(name="blacklisted_license_0E5861", reghex="61 58 0E 00", patch="00 00 00 00"), # EA7E-940129 K-20
    Fix(name="blacklisted_license_0F2747", reghex="47 27 0F 00", patch="00 00 00 00"), # EA7E-993095 Country Rebel
    Fix(name="blacklisted_license_0F6E74", reghex="74 6E 0F 00", patch="00 00 00 00"), # EA7E-1011316 Member J2TeaM
    Fix(name="blacklisted_license_1037E6", reghex="E6 37 10 00", patch="00 00 00 00"), # EA7E-1062886 Yu Li
    Fix(name="blacklisted_license_104F20", reghex="20 4F 10 00", patch="00 00 00 00"), # EA7E-1068832 Bug7sec Team (www.bug7sec.org)
    Fix(name="blacklisted_license_112144", reghex="44 21 11 00", patch="00 00 00 00"), # EA7E-1122628 eldon
    Fix(name="blacklisted_license_1198EB", reghex="EB 98 11 00", patch="00 00 00 00"), # EA7E-1153259 sgbteam
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
    Fix(name="SublimeText", reghex=r"/updates/4/\w+_update_check\?version=\d+&platform=(\w+)&arch=(x64)"),
    Fix(name="SublimeText", reghex=r"/updates/4/\w+_update_check\?version=\d+&platform=(\w+)&arch=(arm64)"),
    Fix(name="SublimeMerge", reghex=r"/updates/\w+_update_check\?version=\d+&platform=(\w+)&arch=(x64)"),
    Fix(name="SublimeMerge", reghex=r"/updates/\w+_update_check\?version=\d+&platform=(\w+)&arch=(arm64)"),
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
