import pefile, re, string

path = r'C:\Users\Administrator\AppData\Roaming\iNmZGdfsvWujhpYZ\umbrella-loader-kernel.dll'
pe = pefile.PE(path, fast_load=True)
minlen = 6
pat = re.compile(rb'[\x20-\x7e]{%d,}' % minlen)
out = []
for s in pe.sections:
    name = s.Name.decode(errors='replace').rstrip('\x00')
    if name not in ('.rdata', '.data', '.rLQ', '._RDATA'):
        d = s.get_data()
        for m in pat.finditer(d):
            out.append((name, m.start(), m.group().decode('ascii', 'ignore')))
print('ASCII strings found:', len(out))
for n, off, txt in out[:120]:
    print('%s+0x%08x  %s' % (n, off, txt))

# UTF-16
patw = re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % minlen)
outw = []
for s in pe.sections:
    name = s.Name.decode(errors='replace').rstrip('\x00')
    d = s.get_data()
    for m in patw.finditer(d):
        outw.append((name, m.start(), m.group().decode('utf-16-le', 'ignore')))
print('WIDE strings found:', len(outw))
for n, off, txt in outw[:80]:
    print('W %s+0x%08x  %s' % (n, off, txt))
