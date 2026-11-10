import frida, base64, os, sys, time, json, threading

PID = int(sys.argv[1]) if len(sys.argv) > 1 else 1272
OUTDIR = r'C:\Umbrella\out_capture'
os.makedirs(OUTDIR, exist_ok=True)

JS = r'''
'use strict';
var MAX_BUF = 3 * 1024 * 1024;
var MAX_TOTAL = 200 * 1024 * 1024;
var total = 0;
var seq = 0;
var counter = 0;
function mod(name) {
    try { return Process.getModuleByName(name); } catch (e) { return null; }
}
function resolve(dll, func) {
    var m = mod(dll);
    if (m && m.getExportByName) { return m.getExportByName(func); }
    // fallback: global export search
    try { return Module.getGlobalExportByName(func); } catch (e2) { return null; }
}
function hookEncrypt() {
    var p = resolve('sspicli.dll', 'EncryptMessage');
    if (!p) { send({ ev: 'note', tag: 'EncryptMessage not found' }); return; }
    Interceptor.attach(p, {
        onEnter: function (args) {
            // args[2] = PSecBufferDesc
            this.desc = args[2];
            var desc = args[2];
            if (desc.isNull()) { this.desc = null; return; }
            var c = desc.add(4).readU32();
            var pb = desc.add(8).readPointer();
            if (pb.isNull()) { this.desc = null; return; }
            for (var i = 0; i < c; i++) {
                var sb = pb.add(i * 16);
                var cb = sb.readU32();
                var ty = sb.add(4).readU32();
                var pv = sb.add(8).readPointer();
                if (ty === 1 && cb > 0 && cb < MAX_BUF) {
                    total += cb;
                    send({ ev: 'buf', dir: 'EM', seq: seq++, size: cb }, pv.readByteArray(Math.min(cb, MAX_BUF)));
                }
            }
        }
    });
}
function hookDecrypt() {
    var p = resolve('sspicli.dll', 'DecryptMessage');
    if (!p) { send({ ev: 'note', tag: 'DecryptMessage not found' }); return; }
    Interceptor.attach(p, {
        onEnter: function (args) { this.desc = args[1]; },
        onLeave: function (r) {
            if (!this.desc || this.desc.isNull()) return;
            var desc = this.desc;
            var c = desc.add(4).readU32();
            var pb = desc.add(8).readPointer();
            if (pb.isNull()) return;
            for (var i = 0; i < c; i++) {
                var sb = pb.add(i * 16);
                var cb = sb.readU32();
                var ty = sb.add(4).readU32();
                var pv = sb.add(8).readPointer();
                if (ty === 1 && cb > 0 && cb < MAX_BUF) {
                    total += cb;
                    send({ ev: 'buf', dir: 'DM', seq: seq++, size: cb }, pv.readByteArray(Math.min(cb, MAX_BUF)));
                }
            }
        }
    });
}
function hookWsaSend() {
    ['WSASend'].forEach(function (n) {
        var p = resolve('ws2_32.dll', n);
        if (!p) return;
        Interceptor.attach(p, {
            onEnter: function (args) {
                var lpBuffers = args[1];
                if (lpBuffers.isNull()) return;
                var count = args[2].toInt32();
                var tcp = 0;
                try {
                    var val = Memory.alloc(4);
                    var len_ptr = Memory.alloc(4);
                    var name = Memory.alloc(16);
                    var proto = Memory.alloc(4);
                    if (getsockopt(args[0], 0xffff, 0x2000 /*SO_PROTOCOL_INFOW not avail*/, val, len_ptr) === 0) {}
                } catch (e) {}
                for (var i = 0; i < count; i++) {
                    var pbuf = lpBuffers.add(i * 16);
                    var len = pbuf.readU32();
                    var bufp = pbuf.add(8).readPointer();
                    if (len > 0 && len < MAX_BUF && total < MAX_TOTAL) {
                        send({ ev: 'buf', dir: 'SEND', seq: seq++, size: len }, bufp.readByteArray(Math.min(len, MAX_BUF)));
                    }
                }
            }
        });
    });
}
function getsockopt(s, lvl, opt, val, lenp) {
    try {
        var gsp = resolve('ws2_32.dll', 'getsockopt');
        return new NativeFunction(gsp, 'int', ['pointer', 'int', 'int', 'pointer', 'pointer'])(s, lvl, opt, val, lenp);
    } catch (e) { return -1; }
}

function hookConnect() {
    var p = resolve('ws2_32.dll', 'connect');
    Interceptor.attach(p, {
        onEnter: function (args) {
            var sa = args[1];
            if (sa.isNull()) return;
            try {
                var fam = sa.readU16();
                if (fam === 2) {
                    var ip = sa.add(4).readU8() + '.' + sa.add(5).readU8() + '.' + sa.add(6).readU8() + '.' + sa.add(7).readU8();
                    var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                    send({ ev: 'conn', ip: ip, port: port });
                }
            } catch (e) {}
        }
    });
}

hookEncrypt();
hookDecrypt();
hookWsaSend();
hookConnect();
send({ ev: 'ready' });
'''

buffer_counts = {'EM': 0, 'DM': 0, 'SEND': 0, 'CONN': 0}
bytes_written = 0


def on_message(message, data):
    global bytes_written
    p = message.get('payload')
    if not isinstance(p, dict):
        print('[msg]', message)
        return
    ev = p.get('ev')
    ts = int(time.time() * 1000)
    if ev == 'buf':
        dirn = p['dir']
        buffer_counts[dirn] = buffer_counts.get(dirn, 0) + 1
        if data:
            bytes_written += len(data)
            name = os.path.join(OUTDIR, '%s.%%05d.%%s.bin' % ts)
            name = name % (p['seq'], dirn)
            with open(name, 'wb') as fh:
                fh.write(data)
        print('[%s] #%s size=%s total_written=%s' % (dirn, p['seq'], p['size'], bytes_written))
    elif ev == 'conn':
        buffer_counts['CONN'] += 1
        line = json.dumps({'ts': ts, 'ip': p['ip'], 'port': p['port']})
        with open(os.path.join(OUTDIR, 'connections.ndjson'), 'a', encoding='utf-8') as fh:
            fh.write(line + '\n')
        print('[CONN] %s:%s' % (p['ip'], p['port']))
    elif ev == 'ready':
        print('[READY] hooks attached')


session = frida.attach(PID)
print('attached to pid', PID)
script = session.create_script(JS)
script.on('message', on_message)
script.load()
print('script loaded, capturing...  Ctrl+C not needed; monitor will terminate us')
while True:
    time.sleep(60)
