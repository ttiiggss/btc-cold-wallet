# Bitcoin-Only Cold Storage Wallet Generator

Zero-dependency, pure-Python 3 Bitcoin key generators for cold storage.
No third-party libraries, no network calls, no dependencies to install or trust.
Every cryptographic primitive — SHA-256, SHA-512, HMAC, PBKDF2, RIPEMD-160,
secp256k1 elliptic-curve math, Base58Check — is implemented from scratch in
plain Python. The only stdlib import is `os` (for `os.urandom`, the OS kernel
CSPRNG; secure randomness cannot be obtained in pure Python).

Both scripts run a built-in self-test against official test vectors on every
launch and abort without generating anything if a primitive is broken.

## Files

| File | What it does |
|------|--------------|
| `bip39_wallet.py` | **Main tool.** Asks for a random number, derives 24 BIP-39 seed words + master private key + 512 receive addresses (BIP-44 path `m/44'/0'/0'/0/i`). Single file, official BIP-39 English wordlist embedded (2048 words, checksummed). |
| `btc_cold_wallet.py` | Simpler single-key generator: one random private key -> WIF + P2PKH address (compressed and uncompressed). |
| `test_btc_cold_wallet.py` | Verification harness (uses hashlib as an independent reference; the wallets themselves import nothing). |

## Usage — cold storage

1. Verify the code (read it — it's short — and/or run the test harness first).
2. Copy the script to an **offline/air-gapped** machine (USB, then wipe the stick).
3. Run:

```
python3 bip39_wallet.py > wallet.txt
```

4. It asks you to type a long random number (dice rolls, digits, keyboard
   mashing). Your input is hashed together with 32 bytes from `os.urandom`,
   so even weak user input cannot reduce the entropy below 256 bits.
5. Write the 24 words on paper or stamp them in metal. Anyone who sees them
   can spend the funds; if you lose them, the funds are gone forever.
6. Fund and monitor addresses using the ADDRESS lines only — addresses can
   safely be checked on any block explorer. Never type the words or private
   key into an online device.

The 512 addresses are all spendable by the same 24 words (standard BIP-44
wallet layout used by Trezor, Ledger, Electrum, Sparrow, etc. — the words can
be restored into any of them).

## Correctness verification

Both scripts self-test on startup against official vectors (Trezor BIP-39
vectors, FIPS 180-4 SHA-256, the RIPEMD-160 spec suite, and documented
Bitcoin keypairs). During development every derivation step was additionally
cross-checked against the independent `bip_utils` library:

- 32 random wallets: mnemonic, BIP-39 seed, master xprv, and derived
  addresses — 192/192 checks identical
- one full wallet: all 512 receive addresses identical to the reference
- SHA-256 matches `hashlib` for all input lengths 0..300 bytes; RIPEMD-160
  matches the official spec suite including the million-'a' vector
- Base58Check payloads with leading zero bytes round-trip (the classic
  hand-rolled-Base58 bug) — 200/200

## Warnings

- P2PKH legacy addresses only (max compatibility, no bech32/SegWit).
- Pure-Python EC math is slow — a few seconds per key, minutes for 512
  addresses. Correctness is unaffected.
- If you printed a key while testing on a networked machine, consider it
  burned; generate real keys only offline.
- No responsibility is taken for lost funds. Verify on small amounts first.

## License

MIT — do whatever you want, but read and understand the code before trusting
it with real money. That is the point of a no-library cold wallet.
