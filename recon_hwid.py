import re, collections

DUMPS = {
    'loader': open(r'C:\Umbrella\dump\UmbrellaLoader_memdump.bin', 'rb').read(),
    'kernel': open(r'C:\Umbrella\dump\kernel_memdump.bin', 'rb').read(),
}

PATTERNS = [
    b'hwid', b'HWID', b'Hwid',
    b'device_id', b'drive_id', b'machine', b'fingerprint', b'Fingerprint', b'FINGERPRINT',
    b'volume', b'Volume', b'serial', b'Serial', b'SERIAL',
    b'smbios', b'SMBIOS', b'mac_addr', b'adapters', b'MAC',
    b'GetVolumeInformation', b'WMI', b'Win32_', b'Select',
    b'steam_provider', b'system_info_provider', b'disk_provider', b'usb_driverkey_provider',
    b'usb_ioctl_provider', b'nvidia_ioctl_provider', b'net_ioctl_provider',
    b'disk_partition_info_provider', b'boot_env_provider', b'display_provider',
    b'registry_provider', b'storage_query_provider',
    b'motherboard', b'bhp', b'BIOS', b'processors', b'CPUID', b'cpuid',
]

for tag, data in DUMPS.items():
    print('=' * 72)
    print('DUMP:', tag, 'size', len(data))
    for k in PATTERNS:
        cnt = data.count(k)
        if not cnt:
            continue
        offs = [m.start() for m in re.finditer(re.escape(k), data)]
        print('\n--- KEY %-26s hits=%d ---' % (k.decode(), cnt))
        # print first few contexts with surrounding printable ASCII
        for off in offs[:6]:
            a, b = max(0, off - 50), off + len(k) + 80
            ctx = re.sub(rb'[^\x20-\x7e]', b'.', data[a:b]).decode()
            print('  0x%09x  %s' % (off, ctx))
