import struct, re

dk = open(r'C:\Umbrella\dump\kernel_memdump.bin', 'rb').read()
base = 0x7ffc0a210000

# provider name offsets (memdump offsets == VA for non-header-remapped regions; here file offset == RVA because we dumped from module base contiguously)
names = [
    'registry_provider', 'storage_query_provider', 'usb_driverkey_provider', 'display_provider',
    'boot_env_provider', 'disk_layout_provider', 'disk_scsi_miniport_provider', 'disk_smart_provider',
    'net_provider', 'netbios_provider', 'smbios_provider', 'tbs_provider', 'monitor_provider',
    'mountmgr_provider', 'dpapi_provider_provider', 'env_var_provider', 'xaudio_provider',
    'audio_provider', 'disk_partition_info_provider', 'system_info_provider', 'steam_provider',
    'net_ioctl_provider', 'usb_ioctl_provider', 'nvidia_ioctl_provider', 'nvidia_nvml_provider',
    'acpi_eval_provider', 'thermal_provider', 'uuid_sequential_provider', 'ntfs_serial_provider',
    'disk_media_serial_provider', 'disk_provider', 'acpi_provider', 'wmi_provider', 'dxgi_provider',
    'efi_provider', 'pci_provider', 'antimalware_provider', 'nvidia_escape_provider',
    'disk_nvme_provider', 'file_provider', 'if_table_provider', 'crypto_storage_provider',
    'discord_provider', 'lsa_sid_provider', 'hid_provider', 'intel_raid_provider',
    'mountdev_unique_id_provider', 'clipc_provider', 'slc_provider', 'monitor_ddc_provider',
    'usb_provider', 'disk_ata_provider',
]

off_by_name = {}
for n, s in zip(names, names):
    idx = dk.find(s.encode())
    if idx >= 0:
        off_by_name[s] = idx

# find qword pointer to each string VA
hits = {}
for n, off in off_by_name.items():
    ptr = base + off
    b = struct.pack('<Q', ptr)
    positions = [m.start() for m in re.finditer(re.escape(b), dk)]
    hits[n] = [(p, ptr) for p in positions]

print('name -> VA occurrences:')
for n in names:
    v = hits.get(n) or []
    if v:
        print('%-32s count=%d  at=%s' % (n, len(v), ['0x%x' % x[0] for x in v]))
    else:
        print('%-32s NOT FOUND' % n)

# Where a cluster of pointer-lozens appears, parse table entries around it
counts = [(n, len(hits[n])) for n in names if hits.get(n)]
clusters = {}
for n, cnt in counts:
    for p, _ in hits[n]:
        clusters.setdefault(p // 0x10000, []).append((p, n))
print()
print('pointer clusters (64K banks):')
for k, v in sorted(clusters.items()):
    print('  bank 0x%08x: %d pointers' % (k * 0x10000, len(v)))

# Take the densest cluster and enumerate surrounding qwords
best = max(clusters.items(), key=lambda kv: len(kv[1]))
bank_start = best[0] * 0x10000
print()
print('=== parse table around densest cluster (bank 0x%08x) ===' % (best[0] * 0x10000))
# collect unique pointer positions
positions = sorted(set(p for p, _ in best[1]))
lo, hi = positions[0] - 0x80, positions[-1] + 0x100
print('scanning qword table 0x%x .. 0x%x (%d bytes)' % (lo, hi, hi - lo))
for a in range(lo, hi, 8):
    val = struct.unpack_from('<Q', dk, a)[0]
    if 0x7ffc00000000 <= val < 0x7ffd00000000:
        rel = val - base
        nm = None
        for n, off in off_by_name.items():
            if abs(off - rel) < 0x400:
                nm = '%s(+0x%x)' % (n, rel - off)
        # decode nearby ascii string for non-name pointers
        vp = None
        for m in re.finditer(rb'[\x20-\x7e]{4,}', dk[max(0, rel-8): rel + 96]):
            if m.start() > 4:
                vp = m.group().decode()
                break
        print('  0x%09x  0x%x  rva=0x%09x  %s  near-str=%s' % (a, val, rel, nm or '', (vp or '')[:60]))
