---
name: encoding-analysis
description: "Encoding identification and decoding: base64, hex, ROT, esoteric languages, QR, custom transforms."
triggers:
  tech: []
  ports: []
  keywords:
    - "encoding"
    - "decode"
    - "base64"
    - "hex"
    - "rot13"
    - "qr code"
    - "brainfuck"
    - "esoteric"
    - "morse"
    - "misc"
    - "obfuscated"
    - "hidden"
    - "challenge"
    - "flag"
priority: 30
required_tools:
  - run_command
---

## Core Pattern

**Re-read the challenge description at least 3 times.** Misc/encoding challenges often hide the key insight in the title, flavor text, or filename. Lateral thinking matters more than tooling.

## Identification (always start here)

```bash
file *
xxd mysterious_file | head -30
cat mysterious_file | head -5
wc -c mysterious_file
```

Check for recognizable patterns:
- Ends with `=` or `==` → likely Base64
- Only `0-9a-fA-F` → hex
- Only `01` and spaces → binary ASCII
- Dots and dashes → Morse code
- `+-<>[].,` only → Brainfuck
- Tabs, spaces, newlines only → Whitespace
- Starts with `{` or `[` → JSON (might contain encoded data)
- Looks like English but shifted → Caesar/ROT

## Common Encodings

### Base64 (including nested)

```bash
echo 'ENCODED' | base64 -d
# Nested base64 (decode multiple times)
echo 'ENCODED' | base64 -d | base64 -d | base64 -d

# Python for robust handling
python3 -c "
import base64
data = open('file.txt', 'rb').read().strip()
while True:
    try:
        data = base64.b64decode(data)
        print(f'Decoded layer: {data[:80]}')
        if b'flag{' in data:
            print(f'FLAG: {data}')
            break
    except:
        print(f'Final: {data}')
        break
"
```

### Base32 / Base85 / Base58

```bash
python3 -c "import base64; print(base64.b32decode('ENCODED'))"
python3 -c "import base64; print(base64.b85decode('ENCODED'))"
python3 -c "import base58; print(base58.b58decode('ENCODED'))"   # pip install base58
```

### Hex

```bash
echo '666c61677b' | xxd -r -p
python3 -c "print(bytes.fromhex('666c61677b'))"
```

### ROT13 / ROT47

```bash
echo 'ENCODED' | tr 'A-Za-z' 'N-ZA-Mn-za-m'                    # ROT13
echo 'ENCODED' | tr '!-~' 'P-~!-O'                               # ROT47
```

### Caesar brute (all 25 shifts)

```bash
python3 -c "
ct = 'CIPHERTEXT'
for shift in range(26):
    pt = ''.join(chr((ord(c) - ord('A') + shift) % 26 + ord('A')) if c.isupper() else
                 chr((ord(c) - ord('a') + shift) % 26 + ord('a')) if c.islower() else c for c in ct)
    print(f'ROT{shift:2d}: {pt}')
"
```

### URL encoding

```bash
python3 -c "from urllib.parse import unquote; print(unquote('ENCODED'))"
```

### Binary ASCII

```bash
python3 -c "
binary = '01100110 01101100 01100001 01100111'
print(''.join(chr(int(b, 2)) for b in binary.split()))"
```

### Decimal ASCII

```bash
python3 -c "print(''.join(chr(int(x)) for x in '102 108 97 103'.split()))"
```

### Octal

```bash
python3 -c "print(''.join(chr(int(x, 8)) for x in '146 154 141 147'.split()))"
```

## QR Codes

```bash
zbarimg qr.png                            # decode QR from image
zbarimg --raw qr.png                      # raw output without prefix

# If image needs preprocessing
convert qr.png -threshold 50% clean_qr.png && zbarimg clean_qr.png

# Multiple QR codes in one image
zbarimg --xml qr.png
```

## Esoteric Languages

### Brainfuck

```bash
# Interpreter
python3 -c "
code = open('program.bf').read()
tape = [0]*30000; ptr = 0; ip = 0; out = []
bracket_map = {}; stack = []
for i, c in enumerate(code):
    if c == '[': stack.append(i)
    if c == ']': j = stack.pop(); bracket_map[j] = i; bracket_map[i] = j
while ip < len(code):
    c = code[ip]
    if c == '>': ptr += 1
    elif c == '<': ptr -= 1
    elif c == '+': tape[ptr] = (tape[ptr] + 1) % 256
    elif c == '-': tape[ptr] = (tape[ptr] - 1) % 256
    elif c == '.': out.append(chr(tape[ptr]))
    elif c == '[' and tape[ptr] == 0: ip = bracket_map[ip]
    elif c == ']' and tape[ptr] != 0: ip = bracket_map[ip]
    ip += 1
print(''.join(out))
"
```

### Whitespace

Characters are only spaces, tabs, and newlines. Use an online interpreter or:

```bash
python3 -c "
# Whitespace interpreter (simplified)
import sys
code = open('program.ws').read()
# ... use a full interpreter
print('Whitespace detected — use online interpreter at https://vii5ard.github.io/whitespace/')
"
```

### Malbolge, Ook!, JSFuck, etc.

Identify by character patterns:
- **Ook!**: `Ook. Ook! Ook? Ook.` → translate to brainfuck
- **JSFuck**: `[](!+)` only → JavaScript, evaluate in Node.js
- **Piet**: Image file that is a program → use `npiet` interpreter

## Custom Protocols / Network Encoding

### HTTP headers / body

```bash
curl -s http://TARGET/ -D - | grep -iE 'flag|x-flag|x-secret|set-cookie'
```

### DNS TXT records

```bash
dig TXT challenge.domain.com
nslookup -type=TXT challenge.domain.com
```

### ICMP data

```bash
tshark -r capture.pcap -Y icmp -T fields -e data | xxd -r -p
```

### Custom encoding in protocol

Look for data hidden in:
- HTTP header values (base64 in Cookie, Authorization)
- DNS subdomain labels (hex/base32 encoded)
- ICMP payload bytes
- TCP sequence numbers

## Transform Techniques

### Reverse string

```bash
echo 'ENCODED' | rev
python3 -c "print('ENCODED'[::-1])"
```

### Vigenere

```python
def vigenere_decrypt(ct, key):
    result = []
    key_idx = 0
    for c in ct:
        if c.isalpha():
            shift = ord(key[key_idx % len(key)].upper()) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            key_idx += 1
        else:
            result.append(c)
    return ''.join(result)

# Brute with common keys or key from challenge hints
```

### XOR brute (single byte)

```bash
python3 -c "
data = bytes.fromhex('HEXDATA')
for k in range(256):
    dec = bytes(b ^ k for b in data)
    if b'flag' in dec.lower():
        print(f'Key {k:#x}: {dec}')
"
```

### Multi-byte XOR with known prefix

```bash
python3 -c "
import itertools
ct = bytes.fromhex('HEXDATA')
known = b'flag{'
key_start = bytes(a ^ b for a, b in zip(ct, known))
print(f'Key starts with: {key_start}')
"
```

### Substitution cipher

```python
from collections import Counter

ct = open('ciphertext.txt').read()
freq = Counter(c for c in ct.upper() if c.isalpha())
print("Frequency:", freq.most_common())
# Compare to English: ETAOINSHRDLCUMWFGYPBVKJXQZ
# Map most frequent → E, second → T, etc.
```

## Lateral Thinking Checklist

When standard decoding fails:

1. **Re-read the challenge name and description** — puns, wordplay, and hints are everywhere.
2. **Check filename** — the name might be the key or algorithm hint.
3. **Look at file size** — suspiciously round? Might be image dimensions or block size.
4. **Try the obvious** — `strings file | grep flag`, `cat file`.
5. **Check if it is multiple encodings chained** — base64 → hex → ROT13.
6. **Reverse the data** — `rev`, read bytes backward.
7. **Check for steganography** — even in "misc" category, a file might hide data.
8. **Look at non-printable bytes** — `xxd file` — patterns in hex might reveal structure.
9. **Google unique strings** — cipher names, encoding schemes, esoteric language names.
10. **Sleep on it** — if stuck after 15 minutes, re-read everything from scratch.

## Workflow

1. `file * && ls -la` — identify all files.
2. `xxd file | head -20` — look at raw bytes.
3. Identify the encoding from patterns above.
4. Decode step by step, checking for `flag{` after each layer.
5. If multi-layered: decode one layer, re-identify, decode next.
6. Verify: `echo 'flag{...}'` — then `SUBMIT_FLAG:`.
