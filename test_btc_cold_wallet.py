#!/usr/bin/env python3
"""
Verification harness for btc_cold_wallet.py.
This file is ONLY for testing on this machine — it uses hashlib as the
independent reference implementation. The wallet itself imports nothing
but os.

Run: python3 test_btc_cold_wallet.py
"""

import hashlib
import random
import sys

sys.path.insert(0, "/home/rjl")
from btc_cold_wallet import (
    sha256, ripemd160, hash160, b58check_encode,
    privkey_to_pubkey, p2pkh_address, wif_compressed, wif_uncompressed, point_mul, _G, _N,
)

random.seed(0xC0FFEE)
failures = []


def chk(name, got, want):
    if got != want:
        failures.append(name)
        print("FAIL %-40s got=%s want=%s" % (name, got, want))
    else:
        print("ok   %s" % name)


# ---------- 1. SHA-256: cross-check vs hashlib over many lengths ----------
print("== SHA-256 vs hashlib, lengths 0..300 ==")
bad = 0
for n in range(0, 301):
    data = bytes(random.getrandbits(8) for _ in range(n))
    if sha256(data) != hashlib.sha256(data).digest():
        bad += 1
        print("  sha256 mismatch at length", n)
if bad == 0:
    print("ok   301/301 lengths match hashlib")
else:
    failures.append("sha256 vs hashlib")

# ---------- 2. RIPEMD-160: official spec vectors ----------
print("== RIPEMD-160 spec vectors ==")
vectors = [
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
    (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
     "b0e20b6e3116640286ed3a87a5713079b21f5189"),
    (b"1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
    (b"a" * 1000000, "52783243c1697bdbe16d37f97f68f08325dc1528"),
]
for msg, want in vectors:
    chk("ripemd160(%dB)" % len(msg), ripemd160(msg).hex(), want)

# ---------- 3. RIPEMD-160 vs hashlib (if OpenSSL provides it) ----------
try:
    hashlib.new("ripemd160")
except Exception as exc:
    print("== RIPEMD-160 vs hashlib: unavailable here (%s) — spec vectors above suffice ==" % exc)
else:
    print("== RIPEMD-160 vs hashlib, lengths 0..300 ==")
    bad = 0
    for n in range(0, 301):
        data = bytes(random.getrandbits(8) for _ in range(n))
        if ripemd160(data) != hashlib.new("ripemd160", data).digest():
            bad += 1
            print("  ripemd160 mismatch at length", n)
    if bad == 0:
        print("ok   301/301 lengths match hashlib")
    else:
        failures.append("ripemd160 vs hashlib")

# ---------- 4. secp256k1 / Base58Check: known Bitcoin keypairs ----------
print("== Bitcoin end-to-end vectors ==")
# private key = 1
cpub, upub = privkey_to_pubkey(1)
chk("pub(1) compressed", cpub.hex(),
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
chk("pub(1) uncompressed", upub.hex(),
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
chk("addr(1) compressed", p2pkh_address(cpub), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
chk("addr(1) uncompressed", p2pkh_address(upub), "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")
chk("wif(1) compressed", wif_compressed("0" * 63 + "1"),
    "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
chk("wif(1) uncompressed", wif_uncompressed("0" * 63 + "1"),
    "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")

# Bitcoin wiki vector
wiki = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
cpub2, upub2 = privkey_to_pubkey(int(wiki, 16))
chk("wiki pub uncompressed", upub2.hex(),
    "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    "2cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6")
chk("wiki addr uncompressed", p2pkh_address(upub2), "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM")

# WIF vector from Bitcoin wiki
chk("wiki wif uncompressed", wif_uncompressed(
    "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"),
    "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")

# ---------- 5. Base58 leading-zero padding round-trip ----------
print("== Base58Check leading-zero padding ==")
alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58_decode(s):
    n = 0
    for ch in s:
        n = n * 58 + alpha.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


bad = 0
for trial in range(200):
    payload = bytes(random.getrandbits(8) for _ in range(random.randrange(1, 40)))
    if random.random() < 0.7:  # force leading zeros often
        payload = b"\x00" * random.randrange(1, 5) + payload
    enc = b58check_encode(payload)
    dec = b58_decode(enc)
    if dec[:len(payload)] != payload:
        bad += 1
if bad == 0:
    print("ok   200/200 payloads with leading zero bytes round-trip")
else:
    failures.append("b58 padding round-trip")

# ---------- 6. EC sanity: G*n for a couple of random k gives points on curve ----------
print("== EC on-curve check ==")
P = 2**256 - 2**32 - 977
bad = 0
for _ in range(5):
    k = random.randrange(1, _N)
    x, y = point_mul(k)
    if (y * y - (x * x * x + 7)) % P != 0:
        bad += 1
if bad == 0:
    print("ok   5/5 random scalar multiples lie on secp256k1")
else:
    failures.append("on-curve check")

print()
if failures:
    print("RESULT: %d FAILURE(S): %s" % (len(failures), ", ".join(failures)))
    sys.exit(1)
print("RESULT: ALL CHECKS PASSED")
