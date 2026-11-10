'use strict';
// UmbrellaLoader observation script (phase 1)
// - hooks process creation, network, file write APIs
// - periodically scans memory for unpacked PE images and reports candidates

var seen = {};      // dedupe memory candidates
var reported = {};  // dedupe event lines

function once(key, line) {
  if (reported[key]) return;
  reported[key] = 1;
  send({ type: 'event', key: key, line: line });
}

function safe(fn) { try { return fn(); } catch (e) { return null; } }

// ---------- process creation ----------
var procHooks = [
  ['CreateProcessW', 'NtCreateFile'], // placeholder
];
function hookProc(name, dll) {
  var p = safe(function () { return Module.getExportByName(dll, name); });
  if (!p) return;
  try {
    Interceptor.attach(p, {
      onEnter: function (args) {
        var cmdline = '';
        if (name.indexOf('CreateProcess') === 0) {
          cmdline = safe(function () { return args[1].readUtf16String(); }) || '';
        } else if (name.indexOf('ShellExecute') === 0) {
          cmdline = safe(function () {
            // ShellExecuteExW: struct->lpFile/lpParameters at offsets 16/24
            var S = args[0];
            var file = S.add(16).readPointer().readUtf16String();
            var params = S.add(24).readPointer().readUtf16String();
            return (file || '') + ' ' + (params || '');
          }) || '';
        } else if (name === 'WinExec') {
          cmdline = safe(function () { return args[0].readAnsiString(); }) || '';
        }
        send({ type: 'proc', api: name, cmd: cmdline });
      }
    });
    send({ type: 'note', tag: 'hooked ' + dll + '!' + name });
  } catch (e) { send({ type: 'note', tag: 'hookfail ' + name + ': ' + e }); }
}

['CreateProcessW', 'CreateProcessA'].forEach(function (n) { hookProc(n, 'kernel32.dll'); });
['ShellExecuteExW', 'ShellExecuteW', 'ShellExecuteA'].forEach(function (n) { hookProc(n, 'shell32.dll'); });
hookProc('WinExec', 'kernel32.dll');

// ---------- network ----------
function sockaddrParse(sa) {
  return safe(function () {
    var fam = sa.readU16();
    if (fam === 2) {
      var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
      var ip = sa.add(4).readU8() + '.' + sa.add(5).readU8() + '.' + sa.add(6).readU8() + '.' + sa.add(7).readU8();
      return 'tcp ' + ip + ':' + port;
    } else if (fam === 23) {
      return 'af6 ' + sa.add(8).readByteArray(16);
    }
    return 'family ' + fam;
  });
}
var con = safe(function () { return Module.getExportByName('ws2_32.dll', 'connect'); });
if (con) {
  Interceptor.attach(con, {
    onEnter: function (args) {
      send({ type: 'net', api: 'connect', info: '' + sockaddrParse(args[1]) });
    }
  });
}
['getaddrinfo', 'GetAddrInfoW', 'gethostbyname'].forEach(function (n) {
  var p = safe(function () { return Module.getExportByName('ws2_32.dll', n); });
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (args) {
      var h = '';
      if (n === 'GetAddrInfoW') h = safe(function () { return args[0].readUtf16String(); }) || '';
      else h = safe(function () { return args[0].readUtf8String(); }) || '';
      send({ type: 'net', api: n, info: h });
    }
  });
});
['send', 'WSASend'].forEach(function (n) {
  var p = safe(function () { return Module.getExportByName('ws2_32.dll', n); });
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (a) {
      var len = (n === 'send') ? a[2].toInt32() : a[3].toInt32();
      send({ type: 'net', api: n, info: 'len=' + len });
    }
  });
});
[['wininet.dll', 'InternetOpenW'], ['wininet.dll', 'InternetOpenUrlA'], ['winhttp.dll', 'WinHttpConnect'], ['winhttp.dll', 'WinHttpSendRequest'], ['urlmon.dll', 'URLDownloadToFileW'], ['urlmon.dll', 'URLDownloadToCacheFileW']].forEach(function (e) {
  var p = safe(function () { return Module.getExportByName(e[0], e[1]); });
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (args) { send({ type: 'net', api: e[1], info: '' }); },
    onLeave: function (r) { send({ type: 'netret', api: e[1], ret: parseInt(r, 10) }); }
  });
  send({ type: 'note', tag: 'hooked ' + e[0] + '!' + e[1] });
});

// ---------- file writes ----------
(function () {
  var p = safe(function () { return Module.getExportByName('kernel32.dll', 'CreateFileW'); });
  if (p) {
    Interceptor.attach(p, {
      onEnter: function (args) {
        this.path = safe(function () { return args[0].readUtf16String(); }) || '';
        this.access = args[1].toInt32().toString(16);
        if ((args[1].toInt32() & 0x40000000) !== 0) { // GENERIC_WRITE
          send({ type: 'file', path: this.path, access: this.access, op: 'write-open' });
        }
      },
      onLeave: function (r) {
        if ((this._access & 0x40000000) !== 0) { /* logged already */ }
      }
    });
  }
  var d = safe(function () { return Module.getExportByName('kernel32.dll', 'DeleteFileW'); });
  if (d) {
    Interceptor.attach(d, { onEnter: function (args) { send({ type: 'file', path: '' + (safe(function () { return args[0].readUtf16String(); }) || ''), op: 'delete' }); } });
  }
})();

// ---------- memory: look for unpacked PE images ----------
function candidates() {
  var found = [];
  var ranges = Process.enumerateRanges({ protection: 'r--', coalesce: false }).concat(
    Process.enumerateRanges({ protection: 'r-x', coalesce: false }).concat(
      Process.enumerateRanges({ protection: 'rwx', coalesce: false })));
  for (var i = 0; i < ranges.length && found.length < 12; i++) {
    var r = ranges[i];
    if (r.size < 0x8000 || r.size > 0x40000000) continue;
    var base = r.base;
    // quick deref: first bytes MZ..ZM handle
    var head = safe(function () { return base.readByteArray(2); });
    if (!head) continue;
    var u8 = new Uint8Array(head);
    if (u8[0] === 0x4D && u8[1] === 0x5A) {
      var lfa = safe(function () { return base.add(0x3c).readU32(); });
      if (lfa && lfa < 0x1000 && lfa < r.size) {
        var pe = safe(function () {
          var b = base.add(lfa).readByteArray(4);
          var v = new Uint8Array(b);
          return v[0] === 0x50 && v[1] === 0x45 && v[2] === 0 && v[3] === 0;
        });
        if (pe) {
          var modCheck = false;
          try {
            var m = Process.findModuleByAddress(base);
            modCheck = !!(m && m.path && m.path.indexOf('UmbrellaLoader') >= 0 && base.equals(m.base));
          } catch (e) { }
          var key = base.toString();
          if (!seen[key]) {
            seen[key] = true;
            found.push({ base: key, size: r.size, mainImage: modCheck });
          }
        }
      }
    }
  }
  return found;
}

var scans = 0;
var timer = setInterval(function () {
  scans++;
  try {
    var f = candidates();
    if (f.length > 0) {
      send({ type: 'scan', round: scans, found: f });
    }
  } catch (e) {
    send({ type: 'note', tag: 'scan error ' + e });
  }
  if (scans >= 10) { clearInterval(timer); send({ type: 'scan-done', rounds: scans }); }
}, 4000);

send({ type: 'note', tag: 'script loaded' });
