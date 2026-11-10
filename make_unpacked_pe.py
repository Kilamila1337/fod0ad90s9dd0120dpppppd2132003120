import struct

src = r'C:\Umbrella\dump\UmbrellaLoader_memdump.bin'
dst = r'C:\Umbrella\dump\UmbrellaLoader_unpacked.exe'
data = bytearray(open(src, 'rb').read())

e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
assert data[e_lfanew:e_lfanew+4] == b'PE\0\0'
coff = e_lfanew + 4
nsec = struct.unpack_from('<H', data, coff+2)[0]
size_opt = struct.unpack_from('<H', data, coff+16)[0]
opt = coff + 20
magic = struct.unpack_from('<H', data, opt)[0]
assert magic == 0x20b
size_of_image = struct.unpack_from('<I', data, opt+56)[0]
file_align = struct.unpack_from('<I', data, opt+36)[0]
sect_align = struct.unpack_from('<I', data, opt+32)[0]
print('nsec', nsec, 'size_opt', hex(size_opt), 'image', hex(size_of_image), 'filealign', hex(file_align), 'sectalign', hex(sect_align))

struct.pack_into('<I', data, opt+16, 0x1000)
struct.pack_into('<I', data, opt+60, 0x1000)

sect = opt + size_opt
names = []
for i in range(nsec):
    off = sect + i*40
    name = data[off:off+8].rstrip(b'\0').decode('latin1')
    vsize, va, rawsize, rawptr = struct.unpack_from('<IIII', data, off+8)
    chars = struct.unpack_from('<I', data, off+36)[0]
    newraw = va
    newsize = (vsize + file_align - 1)//file_align*file_align
    if i == nsec-1:
        newsize = max(newsize, size_of_image - va)
    struct.pack_into('<II', data, off+16, newsize, newraw)
    if name in ('.}jG', '.==]', '.7d)'):
        chars &= ~0x20000000
        struct.pack_into('<I', data, off+36, chars)
    names.append((name, hex(va), hex(vsize), hex(newraw), hex(newsize), hex(chars)))
for n in names:
    print(n)

open(dst, 'wb').write(bytes(data))
print('wrote', dst, len(data))
