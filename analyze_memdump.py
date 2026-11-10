import pefile, re, math, collections, sys

def analysis(path, label):
    print('=' * 70)
    print(label, path)
    data = open(path, 'rb').read()
    pe = pefile.PE(data=data, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    print('imagebase 0x%x  entry 0x%x' % (base, pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    for s in pe.sections:
        va = s.VirtualAddress
        d = data[va: va + s.Misc_VirtualSize if s.Misc_VirtualSize else va + s.SizeOfRawData]
        if not d:
            continue
        c = collections.Counter(d[:0x400000])
        tot = min(len(d), 0x400000)
        e = 0.0
        for v in c.values():
            p = v / tot
            e -= p * math.log2(p)
        print('%-12s va=0x%08x vsz=%9d entropy=%.2f  head=%s' %
              (s.Name.decode(errors='replace'), va, s.Misc_VirtualSize, min(e, 8), d[:16].hex(' ')))
    # strings: ascii
    n1 = 0
    for m in re.finditer(rb'[\x20-\x7e]{8,}', data):
        n1 += 1
    print('ascii strings >=8ch:', n1)
    patw = re.compile(rb'(?:[\x20-\x7e]\x00){8,}')
    n2 = 0
    for m in patw.finditer(data):
        n2 += 1
    print('wide strings >=8ch:', n2)
    return data

dk = analysis(r'C:\Umbrella\dump\kernel_memdump.bin', 'KERNEL memdump')
dl = analysis(r'C:\Umbrella\dump\UmbrellaLoader_memdump.bin', 'LOADER memdump')

open(r'C:\Umbrella\dump\kernel_strings_a.txt', 'w', encoding='utf-8', errors='replace').write(
    '\n'.join(m.group().decode() for m in re.finditer(rb'[\x20-\x7e]{8,}', dk)))
open(r'C:\Umbrella\dump\kernel_strings_w.txt', 'w', encoding='utf-8', errors='replace').write(
    '\n'.join(m.group().decode('utf-16-le', 'ignore') for m in re.finditer(rb'(?:[\x20-\x7e]\x00){8,}', dk)))
open(r'C:\Umbrella\dump\loader_strings_a.txt', 'w', encoding='utf-8', errors='replace').write(
    '\n'.join(m.group().decode() for m in re.finditer(rb'[\x20-\x7e]{8,}', dl)))
open(r'C:\Umbrella\dump\loader_strings_w.txt', 'w', encoding='utf-8', errors='replace').write(
    '\n'.join(m.group().decode('utf-16-le', 'ignore') for m in re.finditer(rb'(?:[\x20-\x7e]\x00){8,}', dl)))
print('strings saved')
