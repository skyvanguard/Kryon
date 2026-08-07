---
name: binary-reverse-engineering
description: "Binary reverse engineering: static/dynamic analysis, symbolic execution, deobfuscation."
triggers:
  tech: []
  ports: []
  keywords:
    - "reverse"
    - "binary"
    - "decompile"
    - "disassemble"
    - "crackme"
    - "obfuscate"
    - "strings"
    - "radare"
    - "ghidra"
    - "angr"
    - "challenge"
    - "flag"
    - "target"
priority: 24
required_tools:
  - run_command
---

## Core Pattern

**strings first → ltrace → angr.** Triage fast before going deep. Most CTF binaries yield to `strings` or a quick `ltrace` run. Only invest in full disassembly or symbolic execution when simpler methods fail.

## Triage (always start here)

```bash
file binary
checksec --file=binary
strings binary | grep -iE 'flag\{|correct|success|wrong|password|enter|input'
rabin2 -z binary | head -40      # printable strings with section info
rabin2 -I binary                 # binary info (arch, endian, canary, pic)
```

Key observations from triage:
- **Stripped?** If yes, no symbol names — focus on entry point and xrefs.
- **Static vs dynamic?** `ldd binary` — static binaries need different debugging approach.
- **Architecture?** x86, x86_64, ARM, MIPS — determines tools and calling convention.

## Static Analysis

### Quick disassembly

```bash
objdump -d binary | grep -A 20 '<main>'
objdump -d binary | grep -B 2 -A 5 'cmp\|test\|jne\|je\|call'
```

### Radare2

```bash
r2 -A binary                    # open with auto-analysis
# Inside r2:
# afl                           — list functions
# pdf @main                     — disassemble main
# iz                            — strings in data section
# axt @sym.check_password       — xrefs to function
# VV @main                      — visual graph mode
```

One-liners for non-interactive use (**VERIFIED working — use these**):

```bash
r2 -A -q -c 'afl' binary                    # list ALL functions
r2 -A -q -c 's main; pdc' binary            # C-like PSEUDOCODE of main (BEST for understanding logic)
r2 -A -q -c 's main; pdf' binary            # disassembly of main
r2 -A -q -c 'iz' binary                     # strings with addresses
r2 -A -q -c 'axt @sym.check_password' binary  # cross-references
r2 -q -c 'aaa; afl' binary
r2 -q -c 'aaa; iz' binary
```

### Ghidra headless

```bash
analyzeHeadless /tmp/ghidra_proj proj -import binary -postScript DecompileAll.java -scriptPath /opt/ghidra/scripts/
# Or use ghidra2json for structured output
```

## Dynamic Analysis

### ltrace / strace

```bash
ltrace ./binary                  # library calls (strcmp, strlen, puts — reveals comparisons)
ltrace -s 200 ./binary <<< "test_input"
strace ./binary                  # system calls (open, read, write)
strace -e trace=read,write ./binary
```

**Key insight:** `ltrace` often reveals the flag directly when the binary uses `strcmp(user_input, "flag{...}")`.

### GDB

```bash
gdb -q binary
# break *main
# run
# info registers
# x/20s $rsp           — examine stack strings
# x/20x $rsp           — examine stack hex
# ni / si              — step over / step into
# set {char}0x... = 0  — patch in memory
```

Useful GDB scripts:

```bash
# Break at strcmp and print arguments
gdb -q -ex 'break strcmp' -ex 'run' -ex 'x/s $rdi' -ex 'x/s $rsi' -ex 'quit' ./binary <<< "AAAA"

# Break at specific address
gdb -q -ex 'break *0x401234' -ex 'run' -ex 'info registers' -ex 'quit' ./binary
```

### Patching branches

Skip a check by replacing a conditional jump with NOP or unconditional jump:

```bash
# Find the jump to patch
r2 -w binary -c 'aaa; s 0x401234; wa jmp 0x401240'
# Or with dd
printf '\x90\x90' | dd of=binary bs=1 seek=$((0x1234)) conv=notrunc
```

## Symbolic Execution with angr

Template for standard crackme (find "correct" path, avoid "wrong" path):

```python
import angr
import claripy

proj = angr.Project('./binary', auto_load_libs=False)

# Option A: find address, avoid address
# Identify these from disassembly (the 'correct' and 'wrong' puts/printf)
FIND_ADDR = 0x401234    # address of success print
AVOID_ADDR = 0x401256   # address of failure print

state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

if simgr.found:
    found = simgr.found[0]
    print(found.posix.dumps(0))  # stdin that reaches the target
```

Template with symbolic stdin of known length:

```python
import angr
import claripy

proj = angr.Project('./binary', auto_load_libs=False)
flag_len = 32
flag = claripy.BVS('flag', flag_len * 8)

state = proj.factory.entry_state(stdin=flag)
# Constrain to printable ASCII
for i in range(flag_len):
    byte = flag.get_byte(i)
    state.solver.add(byte >= 0x20)
    state.solver.add(byte <= 0x7e)

simgr = proj.factory.simgr(state)
simgr.explore(find=lambda s: b'Correct' in s.posix.dumps(1),
              avoid=lambda s: b'Wrong' in s.posix.dumps(1))

if simgr.found:
    print(simgr.found[0].solver.eval(flag, cast_to=bytes))
```

## XOR / Simple Obfuscation

### Single-byte XOR brute

```python
data = open('encoded', 'rb').read()
for key in range(256):
    decoded = bytes(b ^ key for b in data)
    if b'flag{' in decoded or b'FLAG{' in decoded:
        print(f"Key: {key:#x} -> {decoded}")
        break
```

### Multi-byte XOR with known plaintext

```python
known = b'flag{'  # or other known prefix
ct = open('encoded', 'rb').read()
key_fragment = bytes(a ^ b for a, b in zip(ct[:len(known)], known))
print(f"Key fragment: {key_fragment}")
# Extend key if repeating: key = key_fragment * (len(ct) // len(key_fragment) + 1)
```

### Custom encoding

Read the source carefully. Common patterns:
- XOR with index: `ct[i] = pt[i] ^ i`
- Add/subtract constant: `ct[i] = pt[i] + 5`
- Substitution table: extract the table, build inverse
- Base64 variants: non-standard alphabets

## Bytecode / Interpreted Languages

### Python (.pyc)

```bash
uncompyle6 program.pyc > program.py
# Or pycdc for Python 3.9+
pycdc program.pyc
# Manual: disassemble
python3 -c "import dis, marshal; code=marshal.loads(open('program.pyc','rb').read()[16:]); dis.dis(code)"
```

### Java (.class / .jar)

```bash
javap -c -p ClassName.class
# Decompile JAR
cfr ClassName.class
# Or procyon
java -jar procyon-decompiler.jar program.jar -o ./decompiled/
```

### .NET (.exe / .dll)

```bash
# Use dnSpy or ILSpy on Windows, or use dotnet-ildasm
monodis assembly.exe
# ilspycmd (cross-platform)
ilspycmd assembly.dll
```

### JavaScript (Node.js obfuscated)

```bash
# Deobfuscate
node -e "console.log(require('js-beautify').js(require('fs').readFileSync('obfuscated.js','utf8')))"
# Look for eval(), Function(), atob()
```

## Workflow

1. `file binary && checksec --file=binary` — architecture, protections.
2. `strings binary | grep -i flag` — check for hardcoded flag.
3. `ltrace ./binary <<< "test"` — observe library calls, especially `strcmp`.
4. If flag not revealed: disassemble `main` with `r2 -q -c 'aaa; pdf @main' binary`.
5. Identify the check logic (comparison, XOR loop, custom algorithm).
6. Choose approach: manual inversion, GDB patching, or angr symbolic execution.
7. Extract flag, verify: `echo 'flag{...}'` — then `SUBMIT_FLAG:`.
