#!/usr/bin/env python3
"""
verify_against_bip_utils.py — independent cross-verification of bip39_wallet.py.

The wallet itself is zero-dependency; THIS script is test-side only and needs
the well-audited `bip_utils` library as an independent reference:

    python3 -m venv /tmp/refenv
    /tmp/refenv/bin/pip install bip_utils
    /tmp/refenv/bin/python verify_against_bip_utils.py          # 32 random wallets
    /tmp/refenv/bin/python verify_against_bip_utils.py --full   # + all 512 addrs of one wallet

Checks, per random wallet (entropy generated with Python's random, seeded):
  - BIP-39 mnemonic from identical 32-byte entropy matches the reference encoder
  - master xprv (BIP-39 seed -> HMAC-SHA512 "Bitcoin seed" -> BIP-32 serialization) matches
  - first 4 BIP-44 receive addresses (m/44'/0'/0'/0/i) match
With --full: all 512 receive addresses of the Trezor vector mnemonic
"abandon x23 art" are compared one by one.

Exit code 0 = everything matched.
"""
import os
import random
import sys

import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('w', os.path.join(HERE, 'bip39_wallet.py'))
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)  # __main__ guard in the wallet prevents generation at import

from bip_utils import (Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes,
                       Bip39MnemonicEncoder)

FULL = '--full' in sys.argv

random.seed(20260918)  # deterministic test wallets
fails = 0
for t in range(32):
    e = bytes(random.getrandbits(8) for _ in range(32))
    m_mine = w.mnemonic(e)
    m_ref = str(Bip39MnemonicEncoder().Encode(e))
    if m_mine != m_ref:
        fails += 1; print('MNEMONIC MISMATCH trial', t); continue
    s = w.pbkdf2_hmac512(m_mine.encode(), b'mnemonic')
    I = w.hmac512(b'Bitcoin seed', s)
    k, c = int.from_bytes(I[:32], 'big'), I[32:]
    my_xprv = w.xprv(k, c)
    k, c = w.ckd(k, c, 44 + (1 << 31)); k, c = w.ckd(k, c, 1 << 31)
    k, c = w.ckd(k, c, 1 << 31);         k, c = w.ckd(k, c, 0)
    my_addrs = [w.addr(w.ckd(k, c, i)[0]) for i in range(4)]
    mst = Bip44.FromSeed(Bip39SeedGenerator(m_mine).Generate(''), Bip44Coins.BITCOIN)
    ref_xprv = mst.PrivateKey().ToExtended()
    acct = mst.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
    ref_addrs = [acct.AddressIndex(i).PublicKey().ToAddress() for i in range(4)]
    if my_xprv != ref_xprv:
        fails += 1; print('XPRV MISMATCH trial', t, my_xprv, ref_xprv)
    if my_addrs != ref_addrs:
        fails += 1; print('ADDR MISMATCH trial', t, my_addrs, ref_addrs)
print('32-wallet cross-check:', 'FAIL (%d)' % fails if fails else
      'PASS — 32/32 wallets identical (mnemonic + master xprv + 4 addrs each = 192 checks)')

if FULL:
    m = 'abandon ' * 23 + 'art'   # official Trezor 256-bit entropy vector
    s = w.pbkdf2_hmac512(m.encode(), b'mnemonic')
    I = w.hmac512(b'Bitcoin seed', s)
    k, c = int.from_bytes(I[:32], 'big'), I[32:]
    for st in (44 + (1 << 31), 1 << 31, 1 << 31, 0):
        k, c = w.ckd(k, c, st)
    mine = [w.addr(w.ckd(k, c, i)[0]) for i in range(512)]
    acct = Bip44.FromSeed(Bip39SeedGenerator(m).Generate(''), Bip44Coins.BITCOIN) \
        .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
    ref = [acct.AddressIndex(i).PublicKey().ToAddress() for i in range(512)]
    same = mine == ref
    print('512-address full check :', 'PASS — 512/512 identical' if same else 'FAIL')
    if not same:
        fails += 1

sys.exit(1 if fails else 0)
