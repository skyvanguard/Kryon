---
name: evidence-forensics
description: "Digital forensics: PCAP analysis, disk imaging, steganography, artifact recovery."
triggers:
  tech: []
  ports: []
  keywords:
    - "forensic"
    - "pcap"
    - "stego"
    - "steganography"
    - "disk image"
    - "evidence"
    - "artifact"
    - "capture"
    - "packet"
    - "extract"
    - "recover"
    - "hidden"
    - "challenge"
    - "flag"
priority: 23
required_tools:
  - run_command
---

## Core Pattern

**Always grep `flag{` after ANY extraction step.** Forensics flags hide in extracted data, metadata, deleted files, and encoded payloads. Automate the grep — do not rely on visual inspection.

## File Triage (always start here)

```bash
file *
ls -la
xxd suspicious_file | head -20
binwalk -t suspicious_file
```

Check magic bytes manually if `file` gives generic output:
- `89 50 4E 47` → PNG
- `FF D8 FF` → JPEG
- `50 4B 03 04` → ZIP / DOCX / XLSX / JAR
- `1F 8B` → gzip
- `7F 45 4C 46` → ELF binary
- `25 50 44 46` → PDF
- `D0 CF 11 E0` → OLE (DOC, XLS, PPT)

## PCAP Analysis

### Quick wins

```bash
strings capture.pcap | grep -iE 'flag\{|password|secret|key|token'
tshark -r capture.pcap -T fields -e data | xxd -r -p | strings | grep -i flag
```

### Protocol-specific extraction

```bash
# HTTP objects (files transferred)
tshark -r capture.pcap --export-objects http,./http_objects/
ls http_objects/ && grep -rl 'flag' http_objects/

# HTTP request URIs and form data
tshark -r capture.pcap -Y http.request -T fields -e http.request.uri -e http.request.method
tshark -r capture.pcap -Y "http.request.method==POST" -T fields -e http.file_data

# DNS queries (data exfiltration channel)
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | sort -u

# FTP credentials and data
tshark -r capture.pcap -Y ftp -T fields -e ftp.request.command -e ftp.request.arg

# TCP stream reconstruction
tshark -r capture.pcap -z "follow,tcp,ascii,0"
```

### Full ASCII dump

```bash
tcpdump -A -r capture.pcap | grep -i flag
tcpdump -A -r capture.pcap | head -500
```

### Wireless / 802.11

If encrypted: `aircrack-ng capture.pcap -w /usr/share/wordlists/rockyou.txt`, then `airdecap-ng`.

## Disk / Filesystem Images

### Identification and mounting

```bash
file disk.img
fdisk -l disk.img
mmls disk.img         # partition table (sleuthkit)
```

### File listing and recovery

```bash
fls -r -o <offset> disk.img        # list all files (including deleted)
fls -r -d -o <offset> disk.img     # deleted files only
icat -o <offset> disk.img <inode>  # extract specific file by inode
```

### Mount and search

```bash
mkdir /tmp/mnt
mount -o loop,ro disk.img /tmp/mnt
find /tmp/mnt -type f -exec grep -l 'flag{' {} \;
find /tmp/mnt -name "*.txt" -o -name "*.log" -o -name "*.bak" | xargs grep -i flag
ls -la /tmp/mnt/home/*/.bash_history /tmp/mnt/home/*/.ssh/ 2>/dev/null
```

### Automated carving

```bash
foremost -i disk.img -o /tmp/carved
photorec disk.img
```

After carving, **always**:
```bash
grep -rl 'flag{' /tmp/carved/
strings /tmp/carved/* | grep -i flag
```

## Steganography

### PNG — LSB

```bash
zsteg image.png              # tries all LSB combinations
zsteg -a image.png           # aggressive mode, all channels + orders
```

### JPEG — steghide

```bash
steghide extract -sf image.jpg -p ""           # try empty password first
steghide extract -sf image.jpg -p "password"   # common passwords
stegseek image.jpg /usr/share/wordlists/rockyou.txt  # brute-force
```

### Metadata

```bash
exiftool image.*              # EXIF, IPTC, XMP — check Comment field
identify -verbose image.png   # ImageMagick details
```

### Pixel / dimension tricks

```bash
# Check if image dimensions are wrong (CRC mismatch in PNG header)
python3 -c "
import struct, zlib
data = open('image.png', 'rb').read()
# Fix height: try values until CRC matches
ihdr_start = data.index(b'IHDR')
for h in range(1, 2000):
    ihdr = data[ihdr_start:ihdr_start+4] + data[ihdr_start+4:ihdr_start+8] + struct.pack('>I', h) + data[ihdr_start+12:ihdr_start+17]
    if struct.pack('>I', zlib.crc32(ihdr) & 0xFFFFFFFF) == data[ihdr_start+17:ihdr_start+21]:
        print(f'Correct height: {h}')
        break
"
```

### Audio steganography

```bash
# Spectrogram analysis (flag might be visual in spectrogram)
sox audio.wav -n spectrogram -o spectrogram.png
# SSTV (Slow Scan TV)
# Morse code in audio
```

## Archive Recovery

### Corrupt ZIP

```bash
zip -FF broken.zip --out fixed.zip
unzip -t fixed.zip
```

### Password-protected archives

```bash
zip2john protected.zip > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
# For RAR:
rar2john protected.rar > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Embedded archives

```bash
binwalk -e file          # extract all embedded files
foremost -i file -o /tmp/carved
```

## Office Documents / PDF

### OLE (DOC, XLS, PPT)

```bash
olevba document.doc            # extract VBA macros
oleid document.doc             # identify OLE characteristics
oledump.py document.doc        # dump OLE streams
```

### OOXML (DOCX, XLSX, PPTX)

```bash
unzip -d docx_contents document.docx
cat docx_contents/word/document.xml | xmllint --format -
grep -r 'flag' docx_contents/
# Check media folder for embedded images
ls docx_contents/word/media/
```

### PDF

```bash
pdf-parser.py -s flag document.pdf           # search for string
pdf-parser.py -f document.pdf                # show filters
pdftotext document.pdf - | grep -i flag      # extract text
pdfimages document.pdf /tmp/pdfimg           # extract images
# JavaScript in PDF
pdf-parser.py -t javascript document.pdf
```

## Git Forensics

When a challenge involves a `.git` directory or mentions git:

```bash
# Repair + inspect
git fsck -v                          # find corrupt/dangling objects
git log --all --oneline              # full history
git log --all --diff-filter=D -- .   # deleted files
git reflog                           # all HEAD movements including rebases

# Inspect specific objects
git show <commit_hash>               # show commit contents
git diff <hash1> <hash2>             # compare two commits
git cat-file -p <object_hash>        # raw object content (for corrupt repos)

# Recover deleted/hidden content
git stash list && git stash show -p  # stashed changes
git branch -a                        # all branches including remote
for branch in $(git branch -a); do git log --oneline $branch | head -5; done

# Reconstruct corrupt objects (sharpturn-style challenges)
# If git fsck shows bad SHA1: the object bytes were modified
# Find the corrupt blob, hexdump it, fix the corrupted bytes
git fsck --no-dangling 2>&1 | grep "bad sha1"
```

Pattern: **if the challenge hint mentions `git fsck`, the flag is likely hidden in
a corrupted git object that needs byte-level repair.**

## Memory Dumps

```bash
# Volatility 3
vol3 -f memory.dmp windows.info
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.filescan | grep -iE 'flag|secret|password'
vol3 -f memory.dmp windows.cmdline
vol3 -f memory.dmp windows.hashdump
```

## Workflow

1. `ls -la && file *` — identify everything.
2. Run the appropriate triage tool from above based on file type.
3. After EVERY extraction: `grep -ri 'flag{' ./ extracted/ /tmp/carved/ 2>/dev/null`.
4. If no flag found: check metadata (`exiftool`), hidden layers (`binwalk`), alternate data streams.
5. Combine findings — forensics often chains multiple techniques (e.g., PCAP → extract ZIP → steghide on image inside ZIP).
