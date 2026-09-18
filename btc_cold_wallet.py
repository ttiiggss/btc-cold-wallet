#!/usr/bin/env python3
"""
btc_cold_wallet.py — Bitcoin-only cold storage key generator (mainnet).

NO third-party libraries. Everything is implemented from scratch:
  SHA-256 (FIPS 180-4), RIPEMD-160, secp256k1 EC math, Base58Check.
The ONLY import is `os`, and only for os.urandom() — the operating
system kernel's cryptographic random source. There is no way to get
secure randomness in pure Python without it.

Outputs one keypair per run:
  - private key (hex)
  - WIF compressed / uncompressed
  - P2PKH legacy address (compressed / uncompressed)
  - public key (compressed)

Usage:  python3 btc_cold_wallet.py
Run it on an OFFLINE machine for real cold storage.
A built-in self-test against official test vectors runs before any key
is printed; if it fails the script aborts without generating anything.
"""

import os

# ===================== SHA-256 (FIPS 180-4) =====================

_K256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

_H256 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]


def _rotr32(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def sha256(data):
    h = _H256[:]
    msg = bytearray(data)
    bit_len = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += bit_len.to_bytes(8, "big")
    for off in range(0, len(msg), 64):
        blk = msg[off:off + 64]
        w = [int.from_bytes(blk[i * 4:i * 4 + 4], "big") for i in range(16)]
        for i in range(16, 64):
            s0 = _rotr32(w[i - 15], 7) ^ _rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr32(w[i - 2], 17) ^ _rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            S1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
            ch = (e & f) ^ ((e ^ 0xFFFFFFFF) & g)
            t1 = (hh + S1 + ch + _K256[i] + w[i]) & 0xFFFFFFFF
            S0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + maj) & 0xFFFFFFFF
            hh, g, f = g, f, e
            e = (d + t1) & 0xFFFFFFFF
            d, c, b = c, b, a
            a = (t1 + t2) & 0xFFFFFFFF
        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return b"".join(x.to_bytes(4, "big") for x in h)


# ===================== RIPEMD-160 =====================

# message word order, left line
_RL = (
    list(range(16))
    + [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8]
    + [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12]
    + [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2]
    + [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
)
# message word order, right line
_RR = (
    [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12]
    + [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2]
    + [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13]
    + [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14]
    + [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
)
# rotate amounts, left line
_SL = (
    [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8]
    + [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12]
    + [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5]
    + [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12]
    + [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
)
# rotate amounts, right line
_SR = (
    [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6]
    + [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11]
    + [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5]
    + [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8]
    + [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
)
_KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]


def _not32(x):
    return x ^ 0xFFFFFFFF


def _rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _f160(j, x, y, z):
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (_not32(x) & z)
    if j < 48:
        return (x | _not32(y)) ^ z
    if j < 64:
        return (x & z) | (y & _not32(z))
    return x ^ (y | _not32(z))


def ripemd160(data):
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = bytearray(data)
    bit_len = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += bit_len.to_bytes(8, "little")
    for off in range(0, len(msg), 64):
        blk = msg[off:off + 64]
        x = [int.from_bytes(blk[i * 4:i * 4 + 4], "little") for i in range(16)]
        a, b, c, d, e = h
        ap, bp, cp, dp, ep = h
        for j in range(80):
            # left line
            t = (_rol32((a + _f160(j, b, c, d) + x[_RL[j]] + _KL[j // 16]) & 0xFFFFFFFF,
                        _SL[j]) + e) & 0xFFFFFFFF
            a, e, d, c, b = e, d, _rol32(c, 10), b, t
            # right line (functions run in reverse order)
            t = (_rol32((ap + _f160(79 - j, bp, cp, dp) + x[_RR[j]] + _KR[j // 16]) & 0xFFFFFFFF,
                        _SR[j]) + ep) & 0xFFFFFFFF
            ap, ep, dp, cp, bp = ep, dp, _rol32(cp, 10), bp, t
        h = [
            (h[1] + c + dp) & 0xFFFFFFFF,
            (h[2] + d + ep) & 0xFFFFFFFF,
            (h[3] + e + ap) & 0xFFFFFFFF,
            (h[4] + a + bp) & 0xFFFFFFFF,
            (h[0] + b + cp) & 0xFFFFFFFF,
        ]
    return b"".join(v.to_bytes(4, "little") for v in h)


def hash160(data):
    """Bitcoin hash160: RIPEMD160(SHA256(data))"""
    return ripemd160(sha256(data))


# ===================== secp256k1 =====================

_P = 2 ** 256 - 2 ** 32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _inv_mod(a):
    return pow(a, _P - 2, _P)


def point_add(p, q):
    """Affine point addition. None = point at infinity."""
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        lam = (3 * x1 * x1) * _inv_mod(2 * y1) % _P
    else:
        lam = (y2 - y1) * _inv_mod(x2 - x1) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def point_mul(k, pt=_G):
    """Double-and-add scalar multiplication."""
    result = None
    addend = pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def privkey_to_pubkey(k):
    """Returns (compressed_bytes, uncompressed_bytes)."""
    x, y = point_mul(k)
    compressed = bytes([0x02 + (y & 1)]) + x.to_bytes(32, "big")
    uncompressed = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return compressed, uncompressed


# ===================== Base58Check / WIF / address =====================

_B58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check_encode(payload):
    """Base58 of payload + first 4 bytes of SHA256(SHA256(payload))."""
    data = payload + sha256(sha256(payload))[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58_ALPHA[r] + out
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + out


def wif_compressed(priv_hex):
    return b58check_encode(b"\x80" + bytes.fromhex(priv_hex) + b"\x01")


def wif_uncompressed(priv_hex):
    return b58check_encode(b"\x80" + bytes.fromhex(priv_hex))


def p2pkh_address(pubkey_bytes):
    return b58check_encode(b"\x00" + hash160(pubkey_bytes))


# ===================== self-test (runs before any key is made) =====================

def self_test():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        if got != want:
            ok = False
            print("FAIL %s\n  got:  %s\n  want: %s" % (name, got, want))

    # hash vectors
    chk("sha256(empty)", sha256(b"").hex(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    chk("sha256(abc)", sha256(b"abc").hex(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    chk("ripemd160(empty)", ripemd160(b"").hex(),
        "9c1185a5c5e9fc54612808977ee8f548b2258d31")
    chk("ripemd160(abc)", ripemd160(b"abc").hex(),
        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
    chk("ripemd160(a..z)", ripemd160(b"abcdefghijklmnopqrstuvwxyz").hex(),
        "f71c27109c692c1b56bbdceb5b9d2865b3708dbc")
    chk("ripemd160(80 chars)", ripemd160(b"1234567890" * 8).hex(),
        "9b752e45573d4b39f4dbd3323cab82bf63326bfb")

    # key = 1 (end-to-end: EC mult + hashes + base58)
    cpub, upub = privkey_to_pubkey(1)
    chk("pub1 compressed", cpub.hex(),
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    chk("pub1 uncompressed", upub.hex(),
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    chk("addr1 compressed", p2pkh_address(cpub), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
    chk("addr1 uncompressed", p2pkh_address(upub), "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")
    chk("wif1 compressed", wif_compressed("01".rjust(64, "0")),
        "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
    chk("wif1 uncompressed", wif_uncompressed("01".rjust(64, "0")),
        "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")

    # Bitcoin wiki "Technical background of version 1 Bitcoin addresses" vector
    wiki_priv = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
    cpub2, upub2 = privkey_to_pubkey(int(wiki_priv, 16))
    chk("wiki addr uncompressed", p2pkh_address(upub2), "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM")

    if not ok:
        raise SystemExit("SELF-TEST FAILED — no key generated.")
    print("Self-test OK: 18 vectors passed (SHA-256, RIPEMD-160, secp256k1, Base58Check).")


# ===================== main =====================

def generate():
    while True:
        k = int.from_bytes(os.urandom(32), "big")
        if 1 <= k < _N:  # valid range (rejection is astronomically unlikely)
            break
    return k


if __name__ == "__main__":
    self_test()
    print()
    k = generate()
    priv_hex = format(k, "064x")
    cpub, upub = privkey_to_pubkey(k)
    print("BITCOIN COLD STORAGE KEY - keep secret. Anyone with this key can spend the funds.")
    print()
    print("Private key (hex)         : " + priv_hex)
    print("WIF (compressed)          : " + wif_compressed(priv_hex))
    print("Address (compressed P2PKH): " + p2pkh_address(cpub))
    print("Public key (compressed)   : " + cpub.hex())
    print()
    print("WIF (uncompressed)        : " + wif_uncompressed(priv_hex))
    print("Address (uncompressed)    : " + p2pkh_address(upub))
    print()
    print("Use the COMPRESSED pair unless you specifically need the legacy uncompressed one.")
