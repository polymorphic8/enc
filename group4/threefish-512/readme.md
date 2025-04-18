# threefish_cli

**Version:** 0.1.0

## Overview

`threefish_cli` is a command-line utility for in-place file encryption and decryption using the **Threefish-512** tweakable block cipher in CTR mode. It supports:

- Atomic in-place operations: writes to a temporary file and renames it over the original.
- Simple key management: uses a 64-byte raw key from `key.key`, with a `keygen` command to initialize a default key.
- High performance and moderate block size: 512-bit blocks processed in 64-byte chunks.

## Installation

```bash
git clone https://github.com/yourname/threefish_cli.git
cd threefish_cli
cargo build --release
cp target/release/threefish_cli /usr/local/bin/
```

## Usage

```bash
# Generate a default key (creates key.key)
threefish_cli keygen

# Encrypt a file in-place
threefish_cli encrypt myfile.txt

# Decrypt the same file
threefish_cli decrypt myfile.txt
```

## Key and Security

The cipher uses a **64-byte (512-bit)** key loaded from `key.key`. You can replace this file with your own randomly generated key if desired.

The **Threefish-512** cipher provides:

- *Large block size*: 512-bit blocks resist birthday attacks better than 128-bit ciphers.
- *Flexible key size*: up to 512-bit key, here fixed at 512 bits for maximum security margin.
- *Tweakability*: per-block tweaks eliminate the need for external chaining modes.

## Tweakable Block Cipher Explained

A **tweakable block cipher** extends a standard block cipher with an additional *tweak* parameter. Encryption becomes:

```
C = E_{K,T}(P)
```

Where:

- `K` is the secret key.
- `P` is the plaintext block.
- `T` is the *tweak*, a non-secret value that can vary per block.

In `threefish_cli`, we use a 128-bit tweak composed of:

1. **Nonce** (64 bits): randomly generated per file.
2. **Block index** (64 bits): simple counter for each 64-byte chunk.

By varying the tweak for each block, we ensure:

- No two blocks encrypt the same under the same key and tweak.
- No external mode (CTR/CBC) is required for block-level uniqueness.

## Strengths and Trade-offs

`threefish_cli` is ideal when you need:

- Extremely strong theoretical security against generic attacks.
- Large block sizes to minimize collision risks.
- Built-in tweak support for simple domain separation.

However, for general interoperability and hardware acceleration, **AES-256** remains more widely supported.

## License

MIT License. See `LICENSE` file for details.

