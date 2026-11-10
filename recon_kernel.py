import pefile, math, collections

pe = pefile.PE(r'C:\Users\Administrator\AppData\Roaming\iNmZGdfsvWujhpYZ\umbrella-loader-kernel.dll', fast_load=True)
pe.parse_data_directories(directories=[
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IAT'],
])

print('machine', hex(pe.FILE_HEADER.Machine), 'ep', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
      'subsystem', pe.OPTIONAL_HEADER.Subsystem, 'imagebase', hex(pe.OPTIONAL_HEADER.ImageBase))
print('numsections', pe.FILE_HEADER.NumberOfSections, 'timestamp', hex(pe.FILE_HEADER.TimeDateStamp))

for s in pe.sections:
    d = s.get_data()[:0x400000]
    c = collections.Counter(d)
    e = -sum(p / len(d) * math.log2(p / len(d)) for p in c.values() if p)
    print('%-12s va=0x%08x rawsz=%10d entropy=%.3f chars=0x%08x' %
          (s.Name.decode(errors='replace'), s.VirtualAddress, s.SizeOfRawData, e, s.Characteristics))

try:
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        names = [i.name.decode() for i in entry.imports if i.name]
        print('DLL:', entry.dll.decode(), 'imports:', len(names))
        print('   ', ', '.join(names[:40]), '...' if len(names) > 40 else '')
except AttributeError:
    print('NO IMPORT DIRECTORY')

if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
        names = [i.name.decode() for i in entry.imports if i.name]
        print('DELAY DLL:', entry.dll.decode(), 'imports:', len(names), ', '.join(names[:20]))

if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
    t = pe.DIRECTORY_ENTRY_TLS.struct
    print('TLS callbacks @', hex(t.AddressOfCallBacks))

if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
    print('certs:', len(pe.DIRECTORY_ENTRY_SECURITY))

try:
    r = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    if r.VirtualAddress:
        print('has CLR:', hex(r.VirtualAddress))
except Exception:
    pass
