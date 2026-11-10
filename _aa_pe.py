import struct, sys, math, collections

def secs(p):
    d = open(p, 'rb').read()
    e = struct.unpack_from('<I', d, 0x3c)[0]
    nsec, = struct.unpack_from('<H', d, e+6)
    optsz, = struct.unpack_from('<H', d, e+20)
    si, = struct.unpack_from('<I', d, e+24+56)
    st = e+24+optsz
    print('\n== %s  size=%d (0x%x)  SizeOfImage=0x%x' % (p, len(d), len(d), si))
    print('%-12s %10s %10s %10s %10s %10s' % ('name','VA','VSize','RawPtr','RawSize','flags'))
    for i in range(nsec):
        o = st+i*40
        name = d[o:o+8].rstrip(b'\x00').decode('latin1')
        vs, va, rs, rp = struct.unpack_from('<IIII', d, o+8)
        fl, = struct.unpack_from('<I', d, o+36)
        print('%-12s %#10x %#10x %#10x %#10x %#10x' % (name, va, vs, rp, rs, fl))
        # entropy
        if rs:
            blob = d[rp:rp+rs]
            if blob:
                c = collections.Counter(blob)
                ent = -sum((v/len(blob))*math.log2(v/len(blob)) for v in c.values())
                print('    entropy %.3f' % ent)

for p in sys.argv[1:]:
    secs(p)
