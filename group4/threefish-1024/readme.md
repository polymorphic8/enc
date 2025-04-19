# threefish_cli

**Version:** 0.1.0

## Overview

**threefish_cli** is a minimal, high‑security command‑line tool for in‑place file encryption and decryption using the **Threefish‑1024** tweakable block cipher in a CTR‑style mode. It focuses on:

- **Atomic updates**: encrypt/decrypt to a temporary file, then rename over the original to avoid partial writes.
- **Simple key management**: loads a 128‑byte raw key from `key.key` (generated externally).
- **Large block size**: 1024‑bit blocks processed in 128‑byte chunks for maximum security margins.
- **Self‑contained headers**: embeds magic, version, and a per‑file nonce for transparent decryption.

## Installation

```bash
git clone https://github.com/yourname/threefish_cli.git
cd threefish_cli
cargo build --release
cp target/release/threefish_cli /usr/local/bin/
```

> **Note:** You must generate a 128‑byte random key beforehand (e.g. via `openssl rand -out key.key 128`) and place it as `key.key` in the working directory.

## Usage

```bash
# Encrypt a file in-place (writes header + ciphertext)
threefish_cli encrypt path/to/file.bin

# Decrypt the same file (reads header + ciphertext)
threefish_cli decrypt path/to/file.bin
```

- **encrypt `<path>`**: writes a 13‑byte header (`MAGIC|"T1FS"|VERSION|nonce`) followed by ciphertext.
- **decrypt `<path>`**: reads and verifies the header, then restores plaintext.

## File Header Format

Each encrypted file begins with a 13‑byte header:

| Offset | Length | Description                   |
|:------:|:------:|:------------------------------|
| 0      | 4      | ASCII magic: `"T1FS"`         |
| 4      | 1      | Format version (currently `0x01`)
| 5      | 8      | 64‑bit little‑endian nonce    |

The header ensures:

- **Self‑identification**: prevents decrypting random data.
- **Versioning**: future changes remain backward‑compatible.
- **Nonce storage**: required to reconstruct the CTR stream.

## Key Handling & Security

- Expects a **128‑byte** (1024‑bit) key in `key.key`. No built‑in generator—use your own secure source.
- Uses **Threefish‑1024** with a 128‑byte key and 128‑bit tweak (nonce + block index).
- After processing, the in‑memory key is zeroized.

### Why Threefish‑1024?

- **Massive block size** (1024 bits) resists generic birthday/collision attacks far beyond 128‑bit ciphers.
- **Large key space** (up to 1024 bits) provides maximal security margin.
- **Tweakability**: built‑in per‑block tweak (nonce + counter) removes external chaining requirements.

## Tweakable Block Cipher Explained

A **tweakable block cipher** extends a standard block cipher with a non‑secret *tweak* parameter:

```
C = E<sub>K,T</sub>(P)
```

- **K**: secret key (1024 bits)
- **P**: plaintext block (1024 bits)
- **T**: tweak (128 bits) — here composed of:
  1. **Nonce** (64 bits): random per file
  2. **Block index** (64 bits): counter for each 128‑byte chunk

This achieves CTR‑mode security without an external mode: each block’s tweak uniquely separates its keystream.

## Strengths & Trade‑offs

**Strengths**
- Extremely high theoretical security (large blocks + key).
- Built‑in tweak eliminates IV reuse risks.
- Simple, minimal dependencies.

**Trade‑offs**
- Large block size may be slower on some hardware compared to AES.
- Less ubiquitous hardware acceleration vs. AES.
- Requires manual key management.

## License

Released under the **MIT License**. See [LICENSE](LICENSE) for details.

---

*Enjoy strong, tweakable encryption with minimal fuss!*

