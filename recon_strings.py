import re

path = r'C:\Users\Administrator\AppData\Roaming\iNmZGdfsvWujhpYZ\umbrella-loader-kernel.dll'
data = open(path, 'rb').read()
print('file size:', len(data))

keys = ['umbrella', 'Umbrella', 'UMBRELLA', 'dota', 'Dota', 'DOTA', 'deadlock', 'Deadlock',
        'driver', '.sys', '\\\\.\\', 'ntkrnlmp', 'ntoskrnl', 'PiDDB', 'HashCache', 'MmAllocate',
        'inject', 'Inject', 'hook', 'Hook', 'https://', 'http://', 'api/', '/api', 'login',
        'token', 'session', 'auth', 'Auth', '.space', '.zone', 'ws://', 'wss://', 'tcp',
        'kernel32', 'ntdll', 'NtUnload', 'MmUnmap', 'ZwOpen', 'vulnerable', 'iqvw64', 'dbutil',
        'msio', 'f allowable', 'hwid', 'HWID', 'steam', 'STEAM', 'passwd', 'password', 'overlay',
        'D3D11', 'DXGI', 'ImGui', 'imgui', 'render', 'guied', 'Steam', 'main.exe', 'dota2.exe',
        'deadlock.exe', '.exe', 'PDB', 'pdb', 'symbol', 'reloc', 'manualmap', 'ManualMap']

# strings dup
found = {}
for k in keys:
    for m in re.finditer(re.escape(k.encode()), data):
        off = m.start()
        # extract context: ascii printable around
        start = max(0, off - 60)
        end = min(len(data), off + len(k) + 80)
        ctx = data[start:end]
        txt = re.sub(rb'[^\x20-\x7e]', b'.', ctx).decode()
        found.setdefault(k, []).append((off, txt))

for k in keys:
    lst = found.get(k)
    if not lst:
        continue
    print('\n=== KEY: %s (%d hits) ===' % (k, len(lst)))
    for off, txt in lst[:12]:
        print('0x%09x  %s' % (off, txt))
    if len(lst) > 12:
        print('... %d more' % (len(lst) - 12))
