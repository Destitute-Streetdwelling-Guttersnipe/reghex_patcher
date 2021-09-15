# hex_patcher

A patcher working on hex bytes with support for x64 CALL instruction

- hex_patcher is based on the first version of sublime-text-4-patcher by rainbowpigeon
  - refactor the computation of referenced offset in x64 CALL instruction
  - support multiple set of patterns (for various apps, versions ...)
  - use md5 hash on target file to detect which patterns should be applied
  - replace real byte pattern with wildcards, so script-kiddies can't use this
