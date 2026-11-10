import os, re, glob, json

OUT = r'C:\Umbrella\out_capture'

def read_all(pattern):
    items = []
    for path in glob.glob(os.path.join(OUT, pattern)):
        items.append((os.path.basename(path), open(path, 'rb').read()))
    items.sort()
    return items

def sanitize(b):
    return re.sub(rb'[^\x09\x20-\x7e]', b'.', b).decode('utf-8', 'ignore')

print('=' * 78)
for name, d in read_all('*EM.bin'):
    print('--- EM %s (%d bytes) ---' % (name, len(d)))
    print(sanitize(d))
    print()
