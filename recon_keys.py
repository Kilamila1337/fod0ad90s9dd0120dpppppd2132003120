import re

dk = open(r'C:\Umbrella\dump\kernel_memdump.bin', 'rb').read()
dl = open(r'C:\Umbrella\dump\UmbrellaLoader_memdump.bin', 'rb').read()

def ctx(data, off, back=40, fwd=160):
    return re.sub(rb'[^\x20-\x7e]', b'.', data[max(0, off-back): off+fwd]).decode()

def scan(data, label, keys, per=5):
    print('=' * 72)
    print(label)
    for k in keys:
        offs = [m.start() for m in re.finditer(re.escape(k), data)]
        if not offs:
            continue
        print('\n-- %s (%d)' % (k.decode(), len(offs)))
        for off in offs[:per]:
            print('   0x%09x %s' % (off, ctx(data, off)))

scan(dl, 'LOADER: JSON keys', [
    b'providers', b'provider', b'sha256', b'SHA256', b'nonce', b'challenge', b'signature',
    b'email', b'nickname', b'username', b'avatar', b'lifetime', b'server_time',
    b'is_frozen', b'has_active_subsc', b'no_global_freeze', b'can_freeze',
    b'eligibility', b'detailed', b'hwid_reset_available', b'hwid', b'HWID',
    b'product_id', b'subscription_id', b'frozen_until', b'next_freeze', b'until',
    b'days', b'min', b'online', b'game_id', b'session_id', b'device_id',
    b'prompt', b'error_code', b'api_key', b'Public', b'public_key',
    b'x-umbrella', b'Umbrella-', b'umbrella-', b'client_version', b'build',
    b'authorization_code', b'signed', b'ed25519', b'RSA', b'Sealed',
])

scan(dk, 'KERNEL: fingerprint/signature keys', [
    b'providers', b'provider_count', b'hash_algorithm', b'nonce', b'challenge',
    b'ed25519', b'Ed25519', b'Curve25519', b'sha256', b'SHA256', b'sha3', b'blake2',
    b'siphash', b'fnv', b'rollout', b'summ', b'hwsum', b'xor', b'dedup', b'busyset',
    b'build_id', b'version', b'x-umbrella', b'umbrella-', b'game_id', b'product',
    b'subscription', b'device_id', b'fingerprint', b'protocol', b'handler',
    b'providers_disabled', b'major', b'minor',
])
