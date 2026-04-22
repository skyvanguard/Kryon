"""Parse Seizure-Cipher paperscript and render the canvas to image + OCR."""
import re, math, json, sys

body = open('/tmp/sc.html').read()
idx = body.find('paperscript')
start = body.index('>', idx) + 1
end = body.index('</script>', start)
code = body[start:end]
print('code len:', len(code))

m = re.search(r'asdf\s*=\s*\[', code)
start2 = m.end() - 1
depth = 0; i = start2
while i < len(code):
    if code[i] == '[': depth += 1
    elif code[i] == ']':
        depth -= 1
        if depth == 0: break
    i += 1
asdf_block = code[start2+1:i]
print('asdf_block len:', len(asdf_block))

def read_balanced(s, pos):
    assert s[pos] == '('
    depth = 1; pos += 1; buf = []
    while pos < len(s) and depth > 0:
        c = s[pos]
        if c == '(': depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0: return ''.join(buf), pos + 1
        buf.append(c); pos += 1
    raise RuntimeError('eof')

points = []
pos = 0
while True:
    idx = asdf_block.find('new Point(', pos)
    if idx < 0: break
    p = idx + len('new Point')
    inner, p = read_balanced(asdf_block, p)
    depth = 0; split = -1
    for j, c in enumerate(inner):
        if c == '(': depth += 1
        elif c == ')': depth -= 1
        elif c == ',' and depth == 0:
            split = j; break
    if split < 0:
        continue
    x_e = inner[:split]; y_e = inner[split+1:]
    points.append((x_e, y_e))
    pos = p

print('parsed', len(points), 'points')

def jseval(e):
    e = re.sub(r'Math\.(\w+)', r'math.\1', e)
    return eval(e, {'math': math, '__builtins__': {}})

coords = []
errs = 0
for x_e, y_e in points:
    try:
        coords.append((jseval(x_e), jseval(y_e)))
    except Exception as ex:
        errs += 1
        if errs < 3:
            print('err:', ex, 'in:', x_e[:50])
        coords.append(None)

ok = [c for c in coords if c]
print(f'evaluated {len(ok)}/{len(coords)}  errors={errs}')
if ok:
    xs = [c[0] for c in ok]; ys = [c[1] for c in ok]
    print(f'x: {min(xs):.1f}..{max(xs):.1f}  y: {min(ys):.1f}..{max(ys):.1f}')

with open('/tmp/seizure_coords.json', 'w') as f:
    json.dump(ok, f)
print('saved to /tmp/seizure_coords.json')
