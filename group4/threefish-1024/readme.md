# threefish_cli

**Version:** 0.1.0

## Overview

`threefish_cli` is a command-line utility for in-place file encryption and decryption using the **Threefish-1024** tweakable block cipher in CTR mode. It offers:

- **Atomic in-place operations**: writes to a temporary file and renames it over the original.
- **Simple key management**: uses a 128-byte raw key from `key.key`, with a `keygen` command to initialize a default key.
- **Large block size**: 1024-bit blocks processed in 128-byte chunks for high security.

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

- **Key size:** 1024-bit (128-byte) key loaded from `key.key`. Replace this file with your own key for custom deployments.
- **Cipher:** Threefish-1024 offers a massive block size, resisting birthday attacks far better than 128-bit ciphers.
- **Tweak support:** built-in tweaks eliminate the need for external modes for block uniqueness.

## Tweakable Block Cipher Explained

A *tweakable block cipher* extends a standard block cipher with an extra **tweak** input. Encryption is:

```
C = E<sub>K, T</sub>(P)
```

- **K**: secret key
- **P**: plaintext block (1024 bits)
- **T**: tweak (non-secret)

In `threefish_cli`, the tweak is a 128-bit value composed of:

1. **Nonce** (64 bits): a file-specific random value.
2. **Block index** (64 bits): a simple counter (0, 1, 2, …) per 128-byte chunk.

This ensures each block encrypts uniquely without external IVs or chaining.

## Strengths & Trade-offs

**Strengths:**

- Huge theoretical security margin against generic attacks (large key & block sizes).
- Built-in tweakability for domain separation.

**Trade-offs:**

- Less hardware acceleration and ecosystem support compared to AES-256.
- AES-256 remains the industry standard for interoperability.

## License

Released under the **MIT License**. See the `LICENSE` file for details.

