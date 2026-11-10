import re

dk = open(r'C:\Umbrella\dump\kernel_memdump.bin', 'rb').read()
dl = open(r'C:\Umbrella\dump\UmbrellaLoader_memdump.bin', 'rb').read()

def show(data, off, back=120, fwd=200, label=''):
    chunk = data[max(0, off - back): off + fwd]
    txt = re.sub(rb'[^\x20-\x7e]', b'.', chunk).decode()
    print('%s @0x%x : %s' % (label, off, txt))
    print()

print('=== /api/ hits in loader ===')
for m in list(re.finditer(rb'/api/', dl))[:40]:
    show(dl, m.start(), label='L')

print('=== /api/ hits in kernel ===')
for m in list(re.finditer(rb'/api/', dk))[:30]:
    show(dk, m.start(), label='K')

print('=== JWT / auth hints in kernel ===')
for m in list(re.finditer(rb'jwt|JWT|authoriz|Authoriz|token', dk))[:30]:
    show(dk, m.start(), back=60, fwd=120, label='K')
