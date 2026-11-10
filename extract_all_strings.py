import re, os, json
path = r'C:\Umbrella\dump\UmbrellaLoader_reduced.exe'
d = open(path, 'rb').read()
base = 0x7ff7d6c90000
outdir = r'C:\Umbrella\recovered'
os.makedirs(outdir, exist_ok=True)

rows = []
# ASCII printable runs, length >= 4
for m in re.finditer(rb'[\x20-\x7e]{4,}', d):
    s = m.group().decode('latin1')
    rows.append((m.start(), 'a', s))
# UTF-16LE runs
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}', d):
    s = m.group().decode('utf-16-le', 'ignore')
    rows.append((m.start(), 'w', s))
rows.sort()
with open(os.path.join(outdir, 'all_strings.txt'), 'w', encoding='utf-8') as f:
    for off, kind, s in rows:
        f.write(f'{base+off:016x} {off:08x} {kind} {s}\n')
print('strings', len(rows))

# filter interesting
pats = ['http', 'umbrella', 'api/', 'X-Device', 'device', 'auth', 'login', 'subscription',
        'freeze', 'hwid', 'rpc', 'client', 'server', 'product', 'steam', 'discord',
        'dpapi', 'config', 'launcher', 'kernel', 'pdb', 'error_', 'Bearer', 'Authorization',
        'curl', 'update', 'appdata', 'RPC', 'session', 'token']
with open(os.path.join(outdir, 'interesting_strings.txt'), 'w', encoding='utf-8') as f:
    for off, kind, s in rows:
        low = s.lower()
        if any(p.lower() in low for p in pats):
            f.write(f'{base+off:016x} {off:08x} {kind} {s}\n')
print('done')
