import ctypes, os, sys, struct

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

pid = int(sys.argv[1])
outdir = r'C:\Umbrella\dump'
os.makedirs(outdir, exist_ok=True)

h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
if not h:
    print('OpenProcess failed err=%d' % ctypes.get_last_error())
    sys.exit(1)

# args[2:] = pairs base:tag
for arg in sys.argv[2:]:
    parts = arg.split(':')
    base, tag = parts[0], parts[1]
    override_size = int(parts[2], 16) if len(parts) > 2 else None
    base = int(base, 16)
    dos = None
    buf2 = (ctypes.c_char * 0x400)()
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_uint64(base), buf2, 0x400, ctypes.byref(got)):
        print('%s: cannot read header @0x%x err=%d' % (tag, base, ctypes.get_last_error()))
        continue
    dos = buf2.raw
    if dos[:2] != b'MZ':
        print('%s: base 0x%x not MZ' % (tag, base))
        continue
    e_lfanew = struct.unpack_from('<I', dos, 0x3c)[0]
    ntbuf = (ctypes.c_char * 0x800)()
    k32.ReadProcessMemory(h, ctypes.c_uint64(base + e_lfanew), ntbuf, 0x800, ctypes.byref(got))
    nt = ntbuf.raw
    if nt[:4] != b'PE\x00\x00':
        print('%s: no PE at +0x%x' % (tag, e_lfanew))
        continue
    nsec = struct.unpack_from('<H', nt, 6)[0]
    size_of_image = struct.unpack_from('<I', nt, 56)[0]
    if override_size and override_size > size_of_image:
        size_of_image = override_size
    image_base = struct.unpack_from('<Q', nt, 24 + 24)[0]
    entry = struct.unpack_from('<I', nt, 24 + 16)[0]
    print('%s: base=0x%x sizeofimage=0x%x (%.1f MB) nsec=%d entry=0x%x imagebase=0x%x' %
          (tag, base, size_of_image, size_of_image / 1e6, nsec, entry, image_base))
    data = bytearray()
    addr = base
    remaining = size_of_image
    step = 0x400000
    while remaining > 0:
        chunk = min(step, remaining)
        b = (ctypes.c_char * chunk)()
        ok = k32.ReadProcessMemory(h, ctypes.c_uint64(addr), b, chunk, ctypes.byref(got))
        raw = b.raw[:got.value] if got.value else b''
        if len(raw) < chunk:
            raw = raw + b'\x00' * (chunk - len(raw))
        data.extend(raw)
        addr += chunk
        remaining -= chunk
    out = os.path.join(outdir, tag + '_memdump.bin')
    open(out, 'wb').write(bytes(data))
    print('   saved %s (%d bytes)' % (out, len(data)))
print('done')
