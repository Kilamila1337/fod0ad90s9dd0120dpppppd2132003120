import re, struct

path = r'C:\Users\Administrator\AppData\Roaming\iNmZGdfsvWujhpYZ\umbrella-loader-kernel.dll'
data = open(path, 'rb').read()

# Region that contained answer_task_question / auth_client strings
start = 0x16b04a0
end = 0x16b1400
chunk = data[start:end]
names = re.findall(rb'[\x20-\x7e]{4,}', chunk)
print('=== ASCII strings 0x%x..0x%x ===' % (start, end))
for b in names[:200]:
    print(b.decode())

print()
# look for more custom-tagged log lines anywhere
pat = re.compile(rb'\[([A-Z][A-Z0-9_ ]{2,20})\]')
seen = {}
for m in pat.finditer(data):
    tag = m.group(1).decode()
    seen.setdefault(tag, []).append(m.start())
print('=== bracket tags ===')
for tag, offs in sorted(seen.items()):
    print('%-20s %5d hits  first=0x%09x' % (tag, len(offs), offs[0]))
