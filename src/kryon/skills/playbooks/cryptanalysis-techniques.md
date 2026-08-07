---
name: cryptanalysis-techniques
description: "Cryptanalysis attacks: OTP reuse, RSA weaknesses, block cipher exploits, weak RNG recovery."
triggers:
  tech: []
  ports: []
  keywords:
    - "crypto"
    - "cipher"
    - "encrypt"
    - "decrypt"
    - "rsa"
    - "aes"
    - "otp"
    - "xor"
    - "ciphertext"
    - "key recovery"
    - "cryptanalysis"
    - "challenge"
    - "flag"
priority: 22
required_tools:
  - run_command
---

## Core Pattern

**ALWAYS read source first.** Find the encryption function, understand it, then invert it. Do not brute-force blindly when the algorithm is given.

## OTP / XOR Reuse

When the same key encrypts two plaintexts, XOR the ciphertexts to cancel the key:

```
c1 XOR c2 = p1 XOR p2
```

Steps:
1. Identify reused key or nonce (look for identical IV, static key variable, counter reset).
2. XOR ciphertext pairs: `python3 -c "import binascii; c1=bytes.fromhex('...'); c2=bytes.fromhex('...'); print(bytes(a^b for a,b in zip(c1,c2)))"`.
3. Crib drag: guess common plaintext fragments (`flag{`, `the `, `http`) and XOR against the result to recover the other plaintext.
4. Single-byte XOR: brute all 256 keys, score by English character frequency.

```python
from itertools import cycle

def xor_brute(ct: bytes) -> list[tuple[int, bytes]]:
    results = []
    for k in range(256):
        pt = bytes(b ^ k for b in ct)
        score = sum(1 for c in pt if chr(c) in 'etaoinshrdlu ETAOINSHRDLU')
        results.append((score, k, pt))
    return sorted(results, reverse=True)[:5]
```

## RSA Attacks

### Small public exponent (e=3, Hastad's broadcast)

If `m^e < n` (no modular reduction happened): `m = integer_cube_root(c)`.

```python
import gmpy2
m = gmpy2.iroot(c, e)[0]
```

With Hastad broadcast (same m, different n, same small e): use CRT on e ciphertexts, then take e-th root.

### Wiener's attack (small private exponent d)

When `d < n^0.25 / 3`: continued fraction expansion of `e/n` reveals `d`.

```bash
# RsaCtfTool covers this automatically
python3 RsaCtfTool.py --publickey pub.pem --attack wiener --private
```

### Fermat factorization (close primes)

When `|p - q|` is small, `n` factors quickly:

```python
import gmpy2
a = gmpy2.isqrt(n) + 1
b2 = a * a - n
while not gmpy2.is_square(b2):
    a += 1
    b2 = a * a - n
p = a + gmpy2.isqrt(b2)
q = a - gmpy2.isqrt(b2)
```

### Common modulus attack

Same `n`, two different `e` values encrypting same `m`: use extended GCD to recover `m` without factoring.

### FactorDB lookup

Always try `factordb.com` for known factorisations: `run_command("python3 -c \"from factordb.factordb import FactorDB; f=FactorDB(N); f.connect(); print(f.get_factor_list())\"")`.

## Block Cipher Attacks

### ECB detection

Identical plaintext blocks produce identical ciphertext blocks. Feed repeated input, check for repeated 16-byte blocks:

```python
blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
if len(blocks) != len(set(blocks)):
    print("ECB mode detected")
```

ECB cut-and-paste: rearrange ciphertext blocks to forge valid messages.

### CBC padding oracle

When the server leaks whether padding is valid:
1. Use `PadBuster` or manual byte-by-byte decryption.
2. Flip bits in the previous ciphertext block to control decrypted plaintext.
3. Tool: `python3 paddingoracle.py` or `padbuster URL CIPHER BLOCKSIZE`.

### CBC bit-flipping

Flip bit at position `i` in block `C[n-1]` to flip the same bit in plaintext block `P[n]`.

## Frequency Analysis

For classical ciphers (substitution, Vigenere):
1. Letter frequency: compare to English `ETAOINSHRDLU`.
2. Index of coincidence: ~0.065 for English, ~0.038 for random.
3. Kasiski examination for Vigenere key length.
4. Tool: `run_command("python3 -c \"from collections import Counter; ct=open('ct.txt').read(); print(Counter(ct.upper()).most_common(15))\"")`.

### Caesar / ROT brute

```bash
for i in $(seq 0 25); do echo "ROT$i:"; echo 'CIPHERTEXT' | tr "$(printf '%s' {A..Z} | head -c $((26-i)))$(printf '%s' {A..Z} | tail -c $i)" 'A-Z'; done
```

### Vigenere

Once key length `k` is known, split into `k` Caesar ciphers and solve each independently.

## Weak RNG — MT19937

Mersenne Twister state is recoverable from 624 consecutive 32-bit outputs:

```python
# pip install randcrack
from randcrack import RandCrack
rc = RandCrack()
for val in observed_624_values:
    rc.feed(val)
predicted = rc.predict_getrandbits(32)
```

If outputs are truncated, use `z3` to reconstruct full state from partial observations.

## Tools Summary

| Tool | Use case |
|------|----------|
| `pycryptodome` | Python crypto primitives, AES/RSA/DES |
| `RsaCtfTool` | Automated RSA attacks (20+ attack modes) |
| `factordb` | Online factorization database |
| `SageMath` | Number theory, lattice attacks, coppersmith |
| `z3-solver` | Constraint solving, RNG state recovery |
| `randcrack` | MT19937 state prediction |
| `xortool` | Automated XOR key length + key recovery |

## Workflow

1. `ls -la && file *` — identify challenge files.
2. `cat *.py` or `cat *.txt` — read ALL provided source and data.
3. Identify the crypto scheme from the source code.
4. Select the appropriate attack from above.
5. Implement the attack in a Python script, run it.
6. Verify the flag: `echo 'flag{...}'` — then `SUBMIT_FLAG:`.
