import json, re, os

path = r'C:\Umbrella\dump\UmbrellaLoader_reduced.exe'
d = open(path, 'rb').read()
base = 0x7ff7d6c90000

start_rva = 0x7ff7d72f1800 - base
print('start file offset', hex(start_rva), 'bytes', d[start_rva:start_rva+40])

# find the JSON object by scanning for the known first key
needle = b'{\r\n  "Unsupported Windows version'
pos = d.find(needle)
print('json start', hex(pos), 'rva', hex(pos+base))
if pos < 0:
    raise SystemExit

# brace matching with JSON string awareness
i = pos
depth = 0
in_str = False
esc = False
while i < len(d):
    c = d[i:i+1]
    if in_str:
        if esc:
            esc = False
        elif c == b'\\':
            esc = True
        elif c == b'"':
            in_str = False
    else:
        if c == b'"':
            in_str = True
        elif c == b'{':
            depth += 1
        elif c == b'}':
            depth -= 1
            if depth == 0:
                i += 1
                break
    i += 1
blob = d[pos:i]
print('json length', len(blob), 'end rva', hex(pos+len(blob)+base))
print('tail', blob[-80:])
text = blob.decode('utf-8')
try:
    obj = json.loads(text)
    print('parsed keys', len(obj))
    out = r'C:\Umbrella\recovered\strings_en.json'
    os.makedirs(os.path.dirname(out), exist_ok=True)
    open(out, 'w', encoding='utf-8').write(json.dumps(obj, ensure_ascii=False, indent=2))
    print('wrote', out)
except Exception as e:
    print('json parse failed', e)
    open(r'C:\Umbrella\recovered\strings_raw.json', 'wb').write(blob)
