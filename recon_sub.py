import re

dk = open(r'C:\Umbrella\dump\kernel_memdump.bin', 'rb').read()
dl = open(r'C:\Umbrella\dump\UmbrellaLoader_memdump.bin', 'rb').read()

def ctx(data, off, back=60, fwd=140):
    return re.sub(rb'[^\x20-\x7e]', b'.', data[max(0, off-back): off+fwd]).decode()

def scan(data, label, keys, per=6):
    print('=' * 72)
    print(label)
    for k in keys:
        offs = [m.start() for m in re.finditer(re.escape(k), data)]
        if not offs:
            continue
        print('\n-- %s (%d)' % (k.decode(), len(offs)))
        for off in offs[:per]:
            print('   0x%09x %s' % (off, ctx(data, off)))

# subscription-related keys in kernel
scan(dk, 'KERNEL: subscription', [
    b'subscription', b'Subscription', b'freeze', b'Freeze', b'unfreeze', b'eligibility',
    b'expires_at', b'ends_at', b'active', b'banned', b'reset', b'promocode', b'plan',
    b'trial', b'refresh_', b'auth_', b'product', b'Product', b'hwid', b'HWID', b'device',
    b'is_freez', b'remaining', b'left', b'quota', b'session_token', b'refresh_token',
])

# subscription-related keys in loader
scan(dl, 'LOADER: subscription', [
    b'subscription', b'Subscription', b'freeze', b'unfreeze', b'eligibility',
    b'expires', b'active', b'banned', b'reset', b'promocode', b'plan', b'trial',
    b'product', b'Product', b'hwid', b'HWID', b'refresh_client', b'auth_client',
    b'start_product', b'get_server_list', b'answer_task_question', b'device',
    b'remaining', b'session', b'token',
])

# HWID data-source hints in kernel
scan(dk, 'KERNEL: hwid data sources', [
    b'PhysicalDrive', b'Harddisk', b'IOCTL_', b'storage_query', b'SMART', b'scsi_miniport',
    b'nvme', b'NVME', b'\\Device\\', b'WbemServices', b'CIMV2', b'Win32_',
    b'GetAdaptersAddresses', b'GetVolumeInformation', b'DeviceIoControl',
    b'SetupDiGetDeviceRegistryProperty', b'CM_Get', b'EnumAdapters', b'nvapi', b'dxgi',
    b'steam_api', b'ClientLogin', b'DPAPI', b'dpapi', b'lsa_sid', b'LSA', b'discord',
    b'Discord', b'Local State', b'slc', b'SLC', b'clipc', b'ClipC',
])

# HWID data-source hints in loader
scan(dl, 'LOADER: hwid data sources', [
    b'PhysicalDrive', b'\\Device\\', b'WbemServices', b'Win32_', b'DeviceIoControl',
    b'nvapi', b'steam_api', b'dpapi', b'DPAPI', b'discord_conv', b'Local State',
])
