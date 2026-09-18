# Bitcoin-Only Cold Storage Wallet Generator

Zero-dependency, pure-Python 3 Bitcoin key generators for cold storage.
No third-party libraries, no network calls, nothing to install or trust.
Every cryptographic primitive — SHA-256, SHA-512, HMAC-SHA512, PBKDF2-HMAC-SHA512,
RIPEMD-160, secp256k1 elliptic-curve math, Base58Check — is implemented from
scratch in plain Python. The only stdlib import is `os` (for `os.urandom`, the
OS kernel CSPRNG; there is no way to obtain secure randomness in pure Python).

Both wallet scripts run a built-in self-test against official test vectors on
every launch and abort without generating anything if any primitive is broken.

Repo: https://github.com/ttiiggss/btc-cold-wallet

## Files

| File | Lines | What it is |
|------|-------|------------|
| `bip39_wallet.py` | 120 | **Main tool.** Prompts for a random number → 24 BIP-39 seed words + master private key (hex + WIF) + 512 receive addresses (BIP-44 `m/44'/0'/0'/0/i`). Official 2048-word English list embedded. |
| `btc_cold_wallet.py` | 332 | v1 single-key generator: one random private key → WIF + P2PKH address, compressed + uncompressed. Longer because it's the readable/reference implementation. |
| `test_btc_cold_wallet.py` | 157 | Verification harness for v1: cross-checks hashes against `hashlib` (the wallets themselves import nothing). |
| `verify_against_bip_utils.py` | 108 | Reproducible cross-verification of `bip39_wallet.py` against the independent, well-audited `bip_utils` library. |

## Quick start (cold storage)

1. Verify: read the code (it's short), run the test harnesses.
2. Copy to an **offline/air-gapped** machine via USB, then wipe the stick.
3. `python3 bip39_wallet.py > wallet.txt`
4. Type a long random number when prompted (dice rolls, digits, keyboard
   mashing). It is hashed together with 32 bytes of `os.urandom`, so even
   weak user input cannot reduce the entropy below 256 bits.
5. Write the 24 words on paper or stamp them in metal. Anyone with the words
   can spend the funds; lose them and the funds are gone forever.
6. Fund/monitor using the ADDRESS list only — safe to check on any explorer.
   Never type the words or private key into an online device.

The 512 addresses share one seed; the words restore into any standard wallet
(Trezor, Ledger, Electrum, Sparrow — all use BIP-44 `m/44'/0'/0'/0/i`).

---

# Engineering log — everything that was done to create this

This section documents the complete build process, including every dead end
and every bug the verification caught, so the work can be audited and
reproduced. Development machine: Linux, Python 3.12, on 2026-09-18.

## Phase 0 — Ground-truth acquisition (before writing any wallet code)

Two independent ground truths were established first, so that nothing was
ever written from memory:

1. **BIP-39 English wordlist** — fetched from the official BIP-0039 repo
   (`bitcoin/bips`, `bip-0039/english.txt`): 2048 words, SHA-256 verified
   against the digest published in the BIP-39 spec (`2f5eed53…b24dbda`).
2. **Official BIP-39/32 test vectors** — Trezor's `vectors.json` from the
   `trezor/python-mnemonic` repo. Two subtleties were caught at this stage:
   - The Trezor vectors use passphrase `"TREZOR"`. The well-known seed
     `5eb00bbd…` for "abandon…about" is with an **empty** passphrase; the
     `c55257c3…` seed in Trezor's file is the same mnemonic with passphrase
     `"TREZOR"`. Both are asserted in the wallet's self-test.
   - The master key is **not** the seed split in half — it comes from
     `HMAC-SHA512(key="Bitcoin seed", data=seed)`. (More on that below.)
3. **Independent reference implementation** — `bip_utils` installed into a
   throwaway venv (test-side only; the wallet imports nothing). Its API had
   to be probed empirically (wrong method names raised real exceptions:
   `Change(0)` → must be `Change(Bip44Changes.CHAIN_EXT)`, and addresses
   come from `AddressIndex(i).PublicKey().ToAddress()`, not `.Address()`).

## Phase 1 — v1: `btc_cold_wallet.py` (single-key wallet)

Written first as the readable, from-scratch implementation:

- **SHA-256** (FIPS 180-4): K constants, message schedule expansion to 64
  words, working variables a–h, Big-Σ/σ rotations, length padding to 56 mod
  64 + 8-byte big-endian bit length.
- **RIPEMD-160**: dual-line (left/right) 80-step compression with 5 rounds
  of Boolean functions f1–f5, per-line message orders `_RL/_RR`, rotation
  amounts `_SL/_SR`, round constants `KL/KR`, the 10-bit rotation of c/C
  between steps, and the distinctive left-line/right-line combination
  permutation at block end. This is the single buggiest primitive to hand-
  roll; it received the heaviest testing.
- **secp256k1**: curve p = 2²⁵⁶−2³²−977, order n, generator G. Affine
  point addition (case-splitting point-at-infinity, equal-x, general),
  scalar multiplication via double-and-add, modular inverse via
  `pow(a, p−2, p)` (Fermat's little theorem).
- **Base58Check**: payload + first 4 bytes of SHA256(SHA256(payload)),
  repeated divmod by 58, leading-zero → '1' preservation.
- **WIF (mainnet)**: `0x80 || 32-byte key || 0x01` (compressed flag) —
  both compressed and uncompressed WIFs.
- **P2PKH address**: `Base58Check(0x00 || RIPEMD160(SHA256(pubkey)))`,
  both compressed and uncompressed pubkeys.

Verification (harness `test_btc_cold_wallet.py`):
- SHA-256 vs `hashlib.sha256` for all input lengths 0..300 → 301/301 match.
- RIPEMD-160 vs `hashlib.new('ripemd160')` for all lengths 0..300 → 301/301
  match (the OpenSSL in this Python build provides it), plus the 9 official
  spec vectors including the million-'a' one.
- End-to-end known Bitcoin keypairs: private key 1 →
  `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` (compressed) /
  `1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm` (uncompressed); the Bitcoin wiki
  "technical background" vector → `16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM`;
  known WIFs for key 1 (compressed + uncompressed); wiki WIF vector.
- 200/200 Base58Check round-trips on payloads with leading zero bytes (the
  classic hand-rolled Base58 failure mode).
- 5/5 random scalar multiples on-curve (y² = x³ + 7 mod p).
- Import audit via AST walk: the only import is `os`; runs under `python3 -S`
  (no site-packages) to prove zero dependency on installed packages.

## Phase 2 — v2: `bip39_wallet.py` (BIP-39/44, 120-line compact wallet)

User requirements driving the rewrite: a few lines of text, paste-into-a-
text-editor simple; (1) user inputs a random number, (2) outputs private
key + BIP-39 seed words, (3) outputs 500+ addresses.

New primitives layered on v1's core:

- **SHA-512** (FIPS 180-4): 80-round structure, 64-bit words, 128-byte
  blocks, its own 80 K constants, Big-Σ/σ with different rotation amounts,
  16-byte big-endian length field, and — the detail that later bit us — its
  own padding arithmetic (`0x80` then zeros to 111 mod 128).
- **HMAC-SHA512** (RFC 2104): 128-byte block size.
- **PBKDF2-HMAC-SHA512** (RFC 8018): 2048 iterations, single block (64
  bytes ≥ requested length). **Optimization:** instead of computing the
  per-iteration XOR as bytes, the U values are XORed as big integers and
  converted back once, halving per-iteration allocation churn.
- **BIP-39 mnemonic encoding**: entropy (256 bits) || checksum (first 8
  bits of SHA-256(entropy)) → 264 bits → 24 × 11-bit word indices.
- **BIP-32 master key**: `HMAC-SHA512("Bitcoin seed", seed)` → left 32
  bytes = master private key, right 32 = chain code. Extended-key
  serialization (xprv) with version bytes `0x0488ADE4`, depth, fingerprint
  (zeroed at master level), child number, chain code, `0x00`-padded key.
- **BIP-32 CKDpriv**: non-hardened uses the compressed public key in the
  HMAC data; hardened uses `0x00 || ser256(k)`. `(IL + k) mod n` per spec.
- **BIP-44 derivation**: purpose 44' → coin 0' → account 0' → external
  chain 0 → indices 0..511 → P2PKH address per key.

The compact wallet also embeds the entire 2048-word official list inline
(the development template carried a `__WORDLIST__` placeholder substituted
at build time — the file in this repo is the substituted final artifact),
and its self-test asserts 5 official values: the "abandon…about" mnemonic,
both BIP-39 seeds (empty and TREZOR passphrases), the empty-passphrase
master xprv `xprv9s21…PvfUu`, and the BIP-44 first address
`1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA`.

## Phase 3 — The bug hunt (what cross-verification actually caught)

This is the part that matters. Four real bugs were found and fixed. In
three cases the wallet's own self-test **passed while the code was wrong**
— only comparison against `bip_utils` exposed them. Ordered by severity:

### Bug 1 (critical): HMAC-SHA512 did not re-pad hashed long keys

- **Where:** `hmac512()` — `k = sha512(k) if len(k) > 128 else k + pad`.
- **Symptom:** official vectors passed; all 32 random cross-check wallets
  failed at the seed stage.
- **Why the vectors missed it:** the self-test mnemonic "abandon…about" is
  12 words (~85 bytes as UTF-8) — under the 128-byte block size. A 24-word
  mnemonic (~150 bytes) exceeds it, forcing the hash-then-pad path, where
  the code hashed the key but forgot to zero-pad the 64-byte digest back up
  to 128 bytes before XOR with ipad/opad. Exactly the wallet's real use
  case (24 words) was the broken one.
- **Fix:** hash long keys, then always pad to 128 bytes.
- **Lesson:** official short vectors alone cannot certify a hand-rolled
  implementation; randomized differential testing against a reference is
  mandatory.

### Bug 2 (critical): missing "Bitcoin seed" layer entirely

- **Where:** master-key derivation in both selftest and main.
- **Symptom:** xprv assertion failed with a structurally valid but wrong key.
- **Why:** the BIP-39 seed itself had been used as master key material
  (split in half), skipping BIP-32's `HMAC-SHA512("Bitcoin seed", seed)`.
  The Phase-0 vectors captured this rule; the code hadn't caught up.
- **Fix:** insert the HMAC layer in both call sites.

### Bug 3 (major): wrong xprv version magic

- **Where:** `xprv()` serialization — `0x0488AD4E` vs correct `0x0488ADE4`.
- **Symptom:** xprv didn't even start with "xprv" (decoded to "xprY…").
- **Fix:** one byte. The constants were written swapped from memory — a
  reminder not to trust recalled hex constants; derive or verify them.

### Bug 3b (major): chain-code type error

- **Where:** unpacking the HMAC output as two ints (`k, c = [int…, int…]`).
- **Where it bit:** `ckd()` expects a **bytes** chain code (it is the HMAC
  key for child derivation).
- **Fix:** `k` as int, `c` as bytes, consistently everywhere.
- **Note:** the traceback for this one (`can't concat int to bytes`) was
  initially masked by the assert message formatting; reading the actual
  traceback tail located it immediately.

### Also caught in the harness itself

- The first cross-check run reported 32/32 "MNEMONIC MISMATCH" — the
  comparison was wrong, not the wallet: `Bip39MnemonicEncoder().Encode()`
  returns a `Bip39Mnemonic` object, and `!=` against a str is always true.
  Fixed with `str(...)`. Then the real Bug 1 surfaced on the re-run.
- A --full-mode test initially used a hand-typed 25-word mnemonic (invalid
  word count); switched to the vector read directly from Trezor's
  `vectors.json` (`abandon×23 art`) so the ground truth is never retyped
  by hand.

## Phase 4 — Final verification of the exact shipped files

Run against the final committed artifacts (not intermediate states):

| Check | Result |
|-------|--------|
| 32 random wallets: mnemonic + seed→xprv + first 4 BIP-44 addresses each, vs `bip_utils` | **192/192 identical** |
| One full wallet (Trezor "abandon×23 art" 256-bit vector): all 512 receive addresses vs `bip_utils` | **512/512 identical** |
| Wallet startup self-test (5 official asserts) | pass |
| Full run: 512 well-formed P2PKH addresses printed | 512 |
| `python3 -S` (no site-packages) execution | works |
| AST import audit | `os` only |
| All SHA-256/RIPEMD-160/known-keypair checks from Phase 1 | pass |

Reproduce with:

```
python3 -m venv /tmp/refenv && /tmp/refenv/bin/pip install bip_utils
/tmp/refenv/bin/python verify_against_bip_utils.py          # 32 wallets, ~1 min
/tmp/refenv/bin/python verify_against_bip_utils.py --full   # + all 512 addrs, ~5 min
python3 test_btc_cold_wallet.py                             # v1 harness
```

## Design decisions worth recording

- **User entropy is always mixed with `os.urandom(32)`** (SHA-256 of the
  concatenation) before mnemonic generation. User-supplied numbers are
  typically far below 256-bit entropy; mixing guarantees the floor while
  still letting the user add entropy on top.
- **Compressed keys everywhere** in v2; v1 offers both. WIF with `0x01`
  suffix marks compression.
- **P2PKH legacy only.** Bech32/SegWit would add substantially more code
  for a cold-storage reference; legacy maximizes compatibility.
- **Slow by design.** Pure-Python EC math takes minutes for 512 addresses.
  Correctness and auditability over speed; run it once, offline.
- **Self-test before generation, every run.** With no library to trust,
  the script must prove itself each launch against known-answer vectors.

## Limitations / not included

- No bech32 / SegWit / taproot, no multisig, no message signing, no
  transaction building. Key generation only, as specified.
- No BIP-39 passphrase (25th word) prompt. The derivation supports it —
  salt is `b'mnemonic' + passphrase` — but the UI doesn't ask.
- Only the English BIP-39 wordlist.
- Recovery: the words import into any standard BIP-39/44 wallet.

## Warnings

- Any key generated on a networked machine should be considered burned.
  Real cold keys are generated offline only.
- Pure-Python EC math is NOT side-channel hardened. For cold storage on an
  air-gapped single-user machine this is acceptable; do not use this code
  on shared hardware or as a hot-wallet service.
- No warranty. Test with small amounts first. MIT license — read and
  understand the code before trusting it with real money. That is the
  point of a no-library cold wallet.

## License

MIT.
