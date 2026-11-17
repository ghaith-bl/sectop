"""uid systemd gives a DynamicUser= first: SipHash-2-4 of the user name with systemd's
fixed key, folded into the dynamic range (systemd src/core/dynamic-user.c pick_uid(),
PHASE_HASHED; UID_CLAMP_INTO_RANGE). Free -> this uid; taken -> a random one.

Why: sectop-whois runs as a dynamic user. Its processes are invisible to other users
and the user is gone when the lookup ends, so a hostfw line of it had no program
(`? 65258`, host 2026-11-17). hashed("sectop-whois") = 65258: the same number. A uid that
resolves to another name wins (the hash was taken, systemd picked another).
"""

import struct

DYNAMIC_MIN, DYNAMIC_MAX = 61184, 65519            # systemd DYNAMIC_UID_MIN / _MAX
_KEY = bytes((0x37, 0x53, 0x7e, 0x31, 0xcf, 0xce, 0x48, 0xf5,
              0x8a, 0xbb, 0x39, 0x57, 0x8d, 0xd9, 0xec, 0x59))
_M64 = (1 << 64) - 1


def _rotl(x: int, b: int) -> int:
    return ((x << b) | (x >> (64 - b))) & _M64


def siphash24(data: bytes, key: bytes) -> int:
    """SipHash-2-4, 64-bit result (Aumasson / Bernstein)."""
    k0, k1 = struct.unpack("<QQ", key)
    v = [k0 ^ 0x736f6d6570736575, k1 ^ 0x646f72616e646f6d,
         k0 ^ 0x6c7967656e657261, k1 ^ 0x7465646279746573]

    def rounds(n: int) -> None:
        for _ in range(n):
            v[0] = (v[0] + v[1]) & _M64
            v[1] = _rotl(v[1], 13) ^ v[0]
            v[0] = _rotl(v[0], 32)
            v[2] = (v[2] + v[3]) & _M64
            v[3] = _rotl(v[3], 16) ^ v[2]
            v[0] = (v[0] + v[3]) & _M64
            v[3] = _rotl(v[3], 21) ^ v[0]
            v[2] = (v[2] + v[1]) & _M64
            v[1] = _rotl(v[1], 17) ^ v[2]
            v[2] = _rotl(v[2], 32)

    n = len(data)
    end = n - n % 8
    blocks = [struct.unpack("<Q", data[i:i + 8])[0] for i in range(0, end, 8)]
    blocks.append(struct.unpack("<Q", data[end:] + b"\0" * (7 - n % 8) + bytes((n & 0xff,)))[0])
    for m in blocks:
        v[3] ^= m
        rounds(2)
        v[0] ^= m
    v[2] ^= 0xff
    rounds(4)
    return v[0] ^ v[1] ^ v[2] ^ v[3]


def hashed_uid(name: str) -> int:
    """The uid systemd tries first for dynamic user `name` (uid_t cast, then range)."""
    h = siphash24(name.encode(), _KEY) & 0xFFFFFFFF
    return h % (DYNAMIC_MAX - DYNAMIC_MIN + 1) + DYNAMIC_MIN
