import ctypes, ctypes.wintypes as wt, os, sys, struct

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32_exports = k32  # K32EnumProcessModulesEx lives in kernel32.dll on Win7+
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

pid = int(sys.argv[1]) if len(sys.argv) > 1 else 1272
outdir = r'C:\Umbrella\dump'
os.makedirs(outdir, exist_ok=True)
only = sys.argv[2] if len(sys.argv) > 2 else None

h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
if not h:
    print('OpenProcess failed err=%d' % ctypes.get_last_error())
    sys.exit(1)

LIST_MODULES_ALL = 3
count = wt.DWORD()
buf = (ctypes.c_uint64 * 4096)()
if not k32.K32EnumProcessModulesEx(h, buf, ctypes.sizeof(buf), ctypes.byref(count), LIST_MODULES_ALL):
    print('enum failed err=%d' % ctypes.get_last_error())
    sys.exit(1)
print('enum OK, count=%d' % count.value)
# reset error
ctypes.set_last_error(0)
need = wt.DWORD()
n = count.value

bufname = ctypes.create_unicode_buffer(512)
mods = []
for i in range(n):
    hmod = ctypes.c_uint64(buf[i])
    ok = k32.K32GetModuleFileNameExW(h, hmod, bufname, 512)
    if ok:
        mods.append((buf[i], bufname.value))
    else:
        print('GetModuleFileNameExW failed err=%d for h=0x%x' % (ctypes.get_last_error(), buf[i]))

ump = [(b, p) for b, p in mods if 'umbrella' in p.lower()]
print('modules total=%d, umbrella-matching=%d' % (len(mods), len(ump)))
for b, p in mods[:10]:
    print('  mod 0x%x %s' % (b, p))
for b, p in ump:
    print('module base=0x%x  %s' % (b, p))


def rpm(addr, size):
    buf2 = (ctypes.c_char * size)()
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf2, size, ctypes.byref(got)):
        err = ctypes.get_last_error()
        print('RPM failed @0x%x size=0x%x err=%d got=0x%x' % (addr, size, err, got.value))
        return buf2.raw[:got.value]
    return buf2.raw[:got.value]


for base, path in ump:
    if only and only.lower() not in path.lower():
        continue
    name = os.path.basename(path)
    dos = rpm(base, 0x400)
    if dos[:2] != b'MZ':
        print('%s: base 0x%x has no MZ, skipping' % (name, base))
        continue
    e_lfanew = struct.unpack_from('<I', dos, 0x3c)[0]
    nt = rpm(base + e_lfanew, 0x500)
    if nt[:4] != b'PE\x00\x00':
        print('%s: no PE header at e_lfanew=0x%x' % (name, e_lfanew))
        continue
    nsec = struct.unpack_from('<H', nt, 6)[0]
    opt_size = struct.unpack_from('<H', nt, 20)[0]
    size_of_image = struct.unpack_from('<I', nt, 56)[0]
    machine = struct.unpack_from('<H', nt, 4)[0]
    image_base = struct.unpack_from('<Q', nt, 24 + 24)[0]
    entry = struct.unpack_from('<I', nt, 24 + 16)[0]
    print('dump %s: size_of_image=0x%x (%.1f MB) nsec=%d entry=0x%x image_base=0x%x' %
          (name, size_of_image, size_of_image / 1e6, nsec, entry, image_base))
    quanta = 0x100000
    dumped = bytearray()
    addr = base
    remaining = size_of_image
    while remaining > 0:
        chunk = min(quanta, remaining)
        d = rpm(addr, chunk)
        if d is None:
            d = b'\x00' * chunk
        if len(d) < chunk:
            d = d + b'\x00' * (chunk - len(d))
        dumped.extend(d)
        addr += chunk
        remaining -= chunk
    # Rebuild raw file: headers raw then sections laid at VAs (i.e. "memory dump" layout).
    out = os.path.join(outdir, os.path.splitext(name)[0] + '_memdump.bin')
    open(out, 'wb').write(bytes(dumped))
    print('   saved %s (%d bytes)' % (out, len(dumped)))

print('done')
