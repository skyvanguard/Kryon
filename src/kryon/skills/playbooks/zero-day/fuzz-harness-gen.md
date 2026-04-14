---
name: fuzz-harness-gen
description: "Genera harness libFuzzer / AFL++ para una función con input atacante-controlado"
triggers:
  tech: ["c", "cpp", "source_code", "repo"]
  ports: []
  keywords: ["fuzz", "fuzzing", "libfuzzer", "afl", "harness", "coverage-guided"]
priority: 35
required_tools:
  - read_function
  - run_sandboxed
  - find_callers
  - add_to_memory_semantic
---

# Fuzz Harness Generator

When a target function accepts attacker-controlled bytes (parser, decoder, deserializer,
protocol frame handler), generating a libFuzzer or AFL++ harness is the highest-EV
next step — the fuzzer will find inputs the hunter can't reason about.

## When to use

After `zero-day-hunter` identifies a hot function with an input-shaped parameter but
you can't hand-craft a crashing input, OR when the user asks for "fuzzing setup for X".

## libFuzzer harness template (preferred)

libFuzzer is built into Clang and trivially integrated with ASAN. Default output:

```c
// harness.c — build with: clang -g -O1 -fsanitize=fuzzer,address,undefined harness.c target.c -o fuzz_bin
#include <stddef.h>
#include <stdint.h>

// Forward-declare or include the real target symbol
extern int TARGET_FUNCTION(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;
    TARGET_FUNCTION(Data, Size);
    return 0;
}
```

Customize:
- Wrap the call in whatever setup the real function expects (struct init, allocator).
- If the function takes a file descriptor, write `Data` to a tmpfile and pass `fd`.
- If the function takes a C string, ensure null-termination: `char *s = strndup((char*)Data, Size); ...; free(s);`.

## Emit corpus seeds

Always produce 3-5 seed inputs:
1. A known-valid input (parse succeeds without error)
2. A truncated version (cut off mid-record)
3. A boundary input (max size, zero size)
4. A mutation of the valid input (one byte flipped)
5. An intentionally malformed version (wrong magic, bad length)

Emit as `seeds/s01.bin`, `seeds/s02.bin`, ... Generate them inline in the harness
instructions — do not assume the user has them.

## How to verify the harness before handing off

Before declaring the harness ready, validate it:

1. `run_sandboxed(<harness + target code>, language="c")` using the valid seed as
   stdin. Expect `crashed=false`.
2. `run_sandboxed(...)` with a known-bad seed (e.g. stream with truncated header).
   Expect either `crashed=false` (function handled it) or a real crash, not a build error.

If the harness won't even run with the valid seed, the stubs are wrong — fix before
reporting.

## AFL++ variant (when libFuzzer isn't available)

```c
// harness.c — build with afl-clang-fast harness.c target.c -o fuzz_bin
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    unsigned char buf[65536];
    ssize_t n = read(0, buf, sizeof buf);
    if (n <= 0) return 0;
    TARGET_FUNCTION(buf, (size_t)n);
    return 0;
}
```

Instructions to run:
```
mkdir in out
cp seeds/* in/
afl-fuzz -i in -o out -- ./fuzz_bin
```

## Report shape

When emitting a generated harness, structure the output:

```
FUZZ HARNESS
  Target function:  <file>:<function>
  Harness type:     libFuzzer | AFL++
  Build command:    <full clang/afl-clang invocation>
  Harness code:     <C source, <= 60 lines>
  Seed inputs:      <count + brief description of each>
  Verified:         <run_sandboxed result with valid seed>
  Next step:        <command to start the fuzz campaign>
```

## Anti-patterns

- ❌ Emitting a harness that won't compile because dependencies are missing —
  always include the minimum set of `#include`s and any stubbed globals.
- ❌ Skipping the validation step. A harness that segfaults on empty input is
  broken, not a finding.
- ❌ Assuming the user will build + run it. Hand over the exact commands.

---

Fuzzing is the natural escalation path from reasoning-based hunting: the harness is
your handoff to coverage-guided exploration of the input space.
