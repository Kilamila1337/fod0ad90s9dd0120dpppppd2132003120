import re, collections

paths = [r'C:\Umbrella\dump\loader_strings_a.txt', r'C:\Umbrella\dump\loader_strings_w.txt',
         r'C:\Umbrella\dump\kernel_strings_a.txt', r'C:\Umbrella\dump\kernel_strings_w.txt']
# Use original memdumps for complete context extraction (strings files drop separators)
dumps = [r'C:\Umbrella\dump\UmbrellaLoader_memdump.bin', r'C:\Umbrella\dump\kernel_memdump.bin']

found = collections.defaultdict(list)
for d in dumps:
    data = open(d, 'rb').read()
    for m in re.finditer(rb'/api/[A-Za-z0-9_\-/]{2,60}', data):
        found[m.group().decode()].append(d.split('\\')[-1])

print('=== unique /api/ paths ===')
for k in sorted(found):
    srcs = set(found[k])
    print('%-45s %s' % (k, ','.join(sorted(srcs))))

print()
print('=== generic URL-ish strings ===')
seen = set()
for d in dumps:
    data = open(d, 'rb').read()
    for m in re.finditer(rb'(?:https?://|wss?://)[A-Za-z0-9\./:_\-]{5,80}', data):
        s = m.group().decode()
        if s.startswith('http://www.w3.org') or s.startswith('http://www.w') or 'fontawesome' in s or 'sil' in s.lower():
            continue
        if s in seen:
            continue
        seen.add(s)
for s in sorted(seen)[:80]:
    print(s)

print()
print('=== other KEY markers in dumps ===')
keys = [b'umbrella-team', b'uc.zone', b'Bearer', b'JWT', b'jwt', b'Authorization: Bearer',
        b'X-Auth', b'deadlock', b'Deadlock', b'Dota', b'product', b'Product', b'hwid', b'HWID',
        b'drive_id', b'device_id', b'machine_id', b'subscription', b'freezer', b'freeze']
for d in dumps:
    data = open(d, 'rb').read()
    for k in keys:
        cnt = data.count(k)
        if cnt:
            print('%-20s %s hits %d' % (d.split('\\')[-1], k.decode(), cnt))
