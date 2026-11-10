import re
p = r'C:\Umbrella\dump\UmbrellaLoader_memdump.bin'
d = open(p, 'rb').read()
for pat in [b'umbrella-loader-frontend', b'umbrella_loader', b'frontend', b'koval']:
    print('===', pat)
    seen = set()
    for m in re.finditer(pat, d):
        s = max(0, m.start() - 160)
        e = min(len(d), m.end() + 240)
        chunk = d[s:e]
        txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
        key = txt[150:230]
        if key in seen:
            continue
        seen.add(key)
        print(hex(m.start()), txt)
        if len(seen) >= 30:
            break
