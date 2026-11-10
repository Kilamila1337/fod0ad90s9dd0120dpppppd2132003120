import struct, pefile

src = r'C:\Umbrella\dump\UmbrellaLoader_unpacked.exe'
dst = r'C:\Umbrella\dump\UmbrellaLoader_reduced.exe'
data = bytearray(open(src, 'rb').read())

pe = pefile.PE(data=bytes(data))
base = pe.OPTIONAL_HEADER.ImageBase
print('base', hex(base))

# gather imports: dll -> (name, original iat slot rva)
imports = []
iat_base = None
for e in pe.DIRECTORY_ENTRY_IMPORT:
    dll = e.dll.decode()
    for imp in e.imports:
        slot = imp.address - base
        if iat_base is None:
            iat_base = slot
        imports.append((dll, imp.name.decode() if imp.name else f'ord{imp.ordinal}', slot))
print('imports', len(imports), 'iat_base', hex(iat_base))

# layout
IDATA_VA = 0x734000
IDATA_SIZE = 0x3000
IAT_VA = iat_base  # 0xE90000
IAT_SIZE = 0x400

idata = bytearray(IDATA_SIZE)
desc_off = 0
ilt_off = 32 * 20
name_cursor = ilt_off + 32 * 0x10
# name area starts after ILTs

def put_cstr(buf, off, s):
    b = s.encode('latin1') + b'\0'
    buf[off:off+len(b)] = b
    return off + len(b)

# DLL name pool and hint/name entries
dll_names = {}
dll_name_off = {}
hintname_off = {}
# first pass: assign offsets linearly
cur = name_cursor
for i, (dll, fn, slot) in enumerate(imports):
    if dll not in dll_name_off:
        dll_name_off[dll] = cur
        b = dll.encode('latin1') + b'\0'
        idata[cur:cur+len(b)] = b
        cur += len(b)
        cur = (cur + 1) & ~1
# now hint/name entries
for i, (dll, fn, slot) in enumerate(imports):
    hintname_off[i] = cur
    struct.pack_into('<H', idata, cur, 0)
    b = fn.encode('latin1') + b'\0'
    idata[cur+2:cur+2+len(b)] = b
    cur += 2 + len(b)
    cur = (cur + 1) & ~1
print('idata used', hex(cur))

# descriptors and ILTs
for i, (dll, fn, slot) in enumerate(imports):
    d = desc_off + i*20
    ilt = ilt_off + i*0x10
    struct.pack_into('<IIIII', idata, d, IDATA_VA + ilt, 0, 0, IDATA_VA + dll_name_off[dll], slot)
    struct.pack_into('<Q', idata, ilt, IDATA_VA + hintname_off[i])
    struct.pack_into('<Q', idata, ilt+8, 0)
# terminator descriptor
struct.pack_into('<IIIII', idata, desc_off + len(imports)*20, 0,0,0,0,0)

# Build new PE file
out = bytearray(0xE94000)
# copy headers (0x1000)
out[0:0x1000] = data[0:0x1000]
# copy sections
out[0x1000:0x1000+0x522000] = data[0x1000:0x1000+0x522000]
out[0x523000:0x523000+0x208e00] = data[0x523000:0x523000+0x208e00]
out[0x72c000:0x72c000+0x6a00] = data[0x72c000:0x72c000+0x6a00]
out[IDATA_VA:IDATA_VA+IDATA_SIZE] = idata
out[IAT_VA:IAT_VA+IAT_SIZE] = data[IAT_VA:IAT_VA+IAT_SIZE]

# patch PE header
e_lfanew = struct.unpack_from('<I', out, 0x3c)[0]
coff = e_lfanew + 4
opt = coff + 20
size_opt = struct.unpack_from('<H', out, coff+16)[0]
print('e_lfanew', hex(e_lfanew), 'opt', hex(opt), 'size_opt', hex(size_opt))

# number of sections
struct.pack_into('<H', out, coff+2, 5)
# SizeOfImage, SizeOfHeaders
struct.pack_into('<I', out, opt+56, 0xE94000)
struct.pack_into('<I', out, opt+60, 0x1000)
# entry
struct.pack_into('<I', out, opt+16, 0x1000)
# checksum 0
struct.pack_into('<I', out, opt+64, 0)

# data directories: zero all 16, then set import + iat
dd = opt + 112
for i in range(16):
    struct.pack_into('<II', out, dd + i*8, 0, 0)
struct.pack_into('<II', out, dd + 1*8, IDATA_VA, 0x500)   # import
struct.pack_into('<II', out, dd + 12*8, IAT_VA, 0x208)     # IAT

# section table
sect = opt + size_opt
sections = [
    (b'.text\0\0\0', 0x521f96, 0x1000, 0x522000, 0x1000, 0x60000020),
    (b'.rdata\0\0', 0x208c44, 0x523000, 0x208e00, 0x523000, 0x40000040),
    (b'.data\0\0\0', 0x6a00, 0x72c000, 0x6a00, 0x72c000, 0xc0000040),
    (b'.idata\0\0', IDATA_SIZE, IDATA_VA, IDATA_SIZE, IDATA_VA, 0xc0000040),
    (b'.iat\0\0\0\0', IAT_SIZE, IAT_VA, IAT_SIZE, IAT_VA, 0xc0000040),
]
for i, (name, vsz, va, rawsz, rawptr, chars) in enumerate(sections):
    off = sect + i*40
    out[off:off+8] = name
    struct.pack_into('<IIII', out, off+8, vsz, va, rawsz, rawptr)
    struct.pack_into('<II', out, off+24, 0, 0)
    struct.pack_into('<HHI', out, off+32, 0, 0, chars)

open(dst, 'wb').write(bytes(out))
print('wrote', dst, len(out))

# verify
pe2 = pefile.PE(dst)
print('sections')
for s in pe2.sections:
    print(s.Name, hex(s.VirtualAddress), hex(s.Misc_VirtualSize), hex(s.PointerToRawData), hex(s.SizeOfRawData))
print('imports', len(pe2.DIRECTORY_ENTRY_IMPORT))
for e in pe2.DIRECTORY_ENTRY_IMPORT:
    print(e.dll, [(x.name, hex(x.address)) for x in e.imports])
