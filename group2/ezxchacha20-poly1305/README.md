# ezxcha

**Version:** 0.1.0  
**Edition:** 2024

## Overview

`ezxcha` is a command‑line utility to encrypt or decrypt files using **XChaCha20‑Poly1305**. A magic header auto‑detects mode: if the file starts with `XCHACHA20-POLY1305`, it decrypts; otherwise it encrypts—no flags required.

## Features

- XChaCha20-Poly1305 (256-bit key + 192-bit nonce) for modern AEAD security
- Magic header `XCHACHA20-POLY1305` for automatic mode detection
- Safe in-place overwrite using a temporary `.tmp` file

## Installation

Make sure you have [Rust](https://www.rust-lang.org/) (1.65+). Then:

```bash
git clone https://github.com/yourusername/ezxcha.git
cd ezxcha
cargo build --release
```

Binary is at `target/release/ezxcha`.

## Cargo.toml

```toml
[package]
name = "ezxcha"
version = "0.1.0"
edition = "2024"

[dependencies]
chacha20poly1305 = "0.10.1"
rand            = "0.9.1"
```

## Usage

```bash
# Encrypt data.bin → data.bin (overwritten)
./target/release/ezxcha data.bin

# Decrypt an encrypted file
./target/release/ezxcha data.bin
```

## Configuration

Edit `src/main.rs` and replace the example key with your own 32-byte secret:

```rust
let key_bytes: [u8; 32] = [
    0x00, 0x01, 0x02, /* … your random bytes … */
];
```

## Security Considerations

- Keep your key secret (environment variables or a vault).
- XChaCha20-Poly1305’s 192-bit nonce avoids reuse worries, but don’t reuse nonces.
- File sizes are fully loaded into memory—best used on moderate-sized files.

## License

MIT. See the `LICENSE` file.

---

&copy; 2025 Your Name. Built with Rust and [chacha20poly1305](https://crates.io/crates/chacha20poly1305).

