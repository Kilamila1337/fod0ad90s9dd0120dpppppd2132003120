import re

dk = open(r'C:\Umbrella\dump\kernel_memdump.bin', 'rb').read()
dl = open(r'C:\Umbrella\dump\UmbrellaLoader_memdump.bin', 'rb').read()

def strings_region(data, a, b):
    out = []
    for m in re.finditer(rb'[\x20-\x7e]{3,}', data[a:b]):
        out.append((a + m.start(), m.group().decode()))
    return out

print('=' * 70)
print('=== KERNEL .rdata provider registry, offsets 0x169e..0x16a0600 ===')
for off, s in strings_region(dk, 0x169e000, 0x16a0600):
    print('  0x%09x  %s' % (off, s))
