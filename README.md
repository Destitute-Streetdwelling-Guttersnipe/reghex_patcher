# reghex_patcher

A patcher working on hex bytes with support for x64 CALL instruction

- `hex_patcher` (in branch `hex`) is based on the first version of sublime-text-4-patcher by @rainbowpigeon
  - refactor the computation of referenced offset in x64 CALL instruction
  - support multiple set of patterns (for various apps, versions ...)
  - use md5 hash on target file to detect which patterns should be applied
  - replace real byte pattern with wildcards, so script-kiddies can't use this
- `reghex_x64_patcher` (in branch `reghex_x64`) has better support for x64 architecture:
  - use `reghex` instead of hex bytes and wildcards ("?")
  - use regex look-ahead instead of `offset` into hex bytes
  - use regex alternatives ("|") to combine similar patterns
  - generic detection of app, OS ... using lists of `reghex`
  - compute count of NOP bytes based on pre-defined instruction lengths
  - compute referenced offset based on pre-defined instruction lengths
- `reghex_patcher` (in branch `reghex`) improve support for multiple architectures
  - remove computation for x64 architecture (for referenced offset, count of NOP bytes)
  - use regex look-ahead intead of pre-defined instruction lengths (for computation of referenced offset)
  - use pre-defined patch bytes intead of computation for count of NOP bytes
  - better detection of architecture, app, OS ... using 1 list of `reghex`

# what is reghex

- `reghex` is a regex with hex bytes, such as `E8 . . . . (?=C3)`. Hex bytes are 2 hex-digit tokens separated by word boundaries.
- the purpose of `reghex` is to enable the power of regex when searching for patterns in binary data

- `reghex` should be converted to regex by escaping hex bytes, and then used in verbose mode (with flag X)
- unescaped spaces are ignored in `reghex` as well as in regex

# usage

- you must provide list of Fix in class Fixes
- example: `Fix(name="hotfix", reghex="CA FE BA BE", patch="FA CE")` will replace hex bytes `CA FE` with `FA CE`
- there are some pre-defined patches: `nop5`, `ret`, `ret0`, `ret1` ...

# credits

- @leogx9r for signatures and patching logic
- @rainbowpigeon for the first version of sublime-text-4-patcher
