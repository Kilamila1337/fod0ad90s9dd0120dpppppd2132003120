import pefile, re, struct

path = r'C:\Users\Administrator\AppData\Roaming\iNmZGdfsvWujhpYZ\umbrella-loader-kernel.dll'
pe = pefile.PE(path)  # full parse now (was fast_load)
data = open(path, 'rb').read()

print('=== DEBUG DIRECTORY ===')
try:
    for db in pe.DIRECTORY_ENTRY_DEBUG:
        print('type', db.struct.Type, 'ptr', hex(db.struct.PointerToRawData), 'size', db.struct.SizeOfData)
        raw = data[db.struct.PointerToRawData: db.struct.PointerToRawData + db.struct.SizeOfData]
        txt = re.sub(rb'[^\x20-\x7e\n]', b'.', raw).decode()
        print('   ', txt[:400])
except AttributeError:
    print('none')

print('\n=== hexdump around 0x16b0440 (umbrella-loader-kernel.dll) ===')
start = 0x16b0400
chunk = data[start:start + 256]
for i in range(0, 256, 16):
    line = chunk[i:i + 16]
    print('0x%09x  %s  %s' % (start + i, line.hex(' '), ''.join(chr(c) if 0x20 <= c < 0x7f else '.' for c in line)))

print('\n=== hexdump around 0x1551760 (UMBRELLA-CRC32C) ===')
start = 0x1551780
chunk = data[start:start + 160]
for i in range(0, 160, 16):
    line = chunk[i:i + 16]
    print('0x%09x  %s  %s' % (start + i, line.hex(' '), ''.join(chr(c) if 0x20 <= c < 0x7f else '.' for c in line)))

print('\n=== WIDE strings: game/module names ===')
for k in ['dota', 'Dota', 'deadlock', 'Deadlock', 'csgo', 'CSGO', 'steam.exe', 'dota2',
          'umbrella', 'Umbrella', '.exe', '.dll', '.sys', 'http', 'ws://', 'wss://', 'client']:
    pat = re.compile(k.encode('utf-16-le'))
    hits = [m.start() for m in pat.finditer(data)]
    if not hits:
        continue
    print('KEY %s: %d hits' % (k, len(hits)))
    for off in hits[:10]:
        ctx = data[max(0, off - 80): off + 120]
        try:
            # decode as utf-16 chunk aligned: search whole window
            w = ctx.decode('utf-16-le', 'ignore')
            w = re.sub(r'[^\x20-\x7e]', '.', w)
            print('   0x%09x  %s' % (off, w[:120]))
        except Exception as e:
            print('   err', e)
