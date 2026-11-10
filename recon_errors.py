import re, collections, struct

dk = open(r'C:\Umbrella\dump\kernel_memdump.bin', 'rb').read()
dl = open(r'C:\Umbrella\dump\UmbrellaLoader_memdump.bin', 'rb').read()

def uniq(pat, data):
    return sorted(set(m.group().decode() for m in re.finditer(pat, data)))

print('=== unique error_* codes (loader) ===')
for s in uniq(rb'error_[a-z0-9_]{4,50}', dl):
    print('  ' + s)
print()
print('=== unique error_* codes (kernel) ===')
for s in uniq(rb'error_[a-z0-9_]{4,50}', dk):
    print('  ' + s)
print()
print('=== /api/* endpoints (case-insensitive, len until non-url char) ===')
allPaths = set()
for data, tag in [(dl, 'loader'), (dk, 'kernel')]:
    for m in re.finditer(rb'/api/[\x21-\x7e]+', data):
        s = m.group().decode()
        s = s.split(chr(0))[0]
        allPaths.add((tag, s[:60]))
for tag, s in sorted(allPaths):
    print('  [%s] %s' % (tag, s))
print()
print('=== constant pool near SHA256v1 (loader .rdata? kernel .text @0xe5735A) ===')
for start in (0xe57320, 0xe57380):
    chunk = dk[start:start+0x90]
    print('0x%09x  %s' % (start, chunk.hex(' ')))
print()
print('=== search for digest/sig helper names in kernel ===')
for k in [b'HWID', b'hwid', b'fingerprint', b'SHA256v1', b'crc32c', b'CRC32C', b'x64dbg', b'rebuilt']:
    offs = [m.start() for m in re.finditer(re.escape(k), dk)]
    if offs:
        print(k, len(offs), ['0x%x' % x for x in offs[:5]])
