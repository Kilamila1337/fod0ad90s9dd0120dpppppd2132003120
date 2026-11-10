import os, re, glob, json, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

OUT = r'C:\Umbrella\out_capture'

files = sorted(glob.glob(os.path.join(OUT, '*DM.bin')) + glob.glob(os.path.join(OUT, '*SEND.bin')))

# TLS records fragment HTTP responses; reconstruct by looking for HTTP headers or JSON objects in a sliding window over each fragment and its predecessor
def sanitize(b):
    return re.sub(rb'[^\x09\x20-\x7e]', b'\x00', b)

interesting_keys = [
    b'has_active_subsc', b'frozen_until', b'can_freeze', b'eligib', b'subscription',
    b'username', b'avatar', b'email', b'user_id', b'hwid', b'device', b'expires',
    b'trial', b'lifetime', b'product', b'server', b'session', b'2fa', b'country',
]

# 1. Extract all JSON objects from all DM fragments (holders of /api/user/me etc.)
# Simple approach: scan each file for balanced {..} regions containing "key":value
json_found = []
for path in files:
    data = open(path, 'rb').read()
    s = data
    n = len(s)
    i = 0
    while i < n:
        c = s.find(b'{', i)
        if c < 0:
            break
        # attempt to close
        depth = 0
        j = c
        in_str = False
        esc = False
        end = -1
        while j < n:
            ch = s[j:j+1]
            if in_str:
                if esc:
                    esc = False
                elif ch == b'\\':
                    esc = True
                elif ch == b'"':
                    in_str = False
            else:
                if ch == b'"':
                    in_str = True
                elif ch == b'{':
                    depth += 1
                elif ch == b'}':
                    depth -= 1
                    if depth == 0:
                        end = j
                        break
            j += 1
        if end < 0:
            # fragmented JSON (spans TLS records) - join with next files? handle later
            break
        blob = s[c:end+1]
        if any(k in blob for k in interesting_keys) and b'{' in blob and len(blob) < 20000:
            try:
                obj = json.loads(blob.decode('utf-8', 'replace'))
                json_found.append((os.path.basename(path), c, obj))
                i = end + 1
                continue
            except Exception:
                pass
        i = c + 1

print('=== JSON objects with interesting keys (%d found) ===' % len(json_found))
for name, off, obj in json_found[:60]:
    txt = json.dumps(obj, ensure_ascii=False)
    print('[%s @0x%x] %s' % (name, off, txt[:1200]))
    print()

# 2. HTTP response headers: find "HTTP/1.1 ... " and content-length etc across fragments
print('=== HTTP response headers found ===')
hdr_seen = set()
for path in files:
    data = open(path, 'rb').read()
    for m in re.finditer(rb'HTTP/1\.1 \d{3}[^\x00]{0,600}', data):
        h = m.group()
        end = h.find(b'\r\n\r\n')
        if end > 0:
            h = h[:end]
        t = sanitize(h).replace('\x00', '.')
        key = t[:120]
        if key not in hdr_seen:
            hdr_seen.add(key)
            print('[%s]' % os.path.basename(path))
            print(t)
            print()
