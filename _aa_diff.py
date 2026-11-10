import struct, math, collections, sys

def sections(p):
    d = open(p,'rb').read()
    e = struct.unpack_from('<I', d, 0x3c)[0]
    nsec, = struct.unpack_from('<H', d, e+6)
    optsz, = struct.unpack_from('<H', d, e+20)
    st = e+24+optsz
    out=[]
    for i in range(nsec):
        o=st+i*40
        name=d[o:o+8].rstrip(b'\x00').decode('latin1')
        vs,va,rs,rp=struct.unpack_from('<IIII',d,o+8)
        out.append((name,va,vs,rs,rp))
    return d,out

disk,ds = sections(r'dump\umbrella-loader-kernel.dll')
mem,ms  = sections(r'dump\kernel_memdump.bin')

def ent(b):
    if not b: return 0
    c=collections.Counter(b)
    return -sum((v/len(b))*math.log2(v/len(b)) for v in c.values())

# memory image offsets == VA (image layout), disk uses raw ptr
for (n,va,vs,rs,rp) in ds:
    memblob = mem[va:va+vs]
    diskblob = disk[rp:rp+min(rs,vs)]
    diff = sum(1 for a,b in zip(diskblob, memblob[:len(diskblob)]) if a!=b)
    print('%-10s vsize=%9d  diff_bytes=%9d (%.1f%%)  diskE=%.2f memE=%.2f' % (
        n, vs, diff, 100.0*diff/max(1,len(diskblob)), ent(diskblob), ent(memblob)))
