# filecrypt

`filecrypt` is a small, production-grade CLI tool for in-place file encryption and decryption using libsodium’s SecretStream (XChaCha20-Poly1305). It provides atomic overwrites, format versioning, and strict key verification to ensure safety and reliability even for large files.

---

## Features

- **Streaming encryption/decryption**: Processes files in 64 KiB chunks without buffering entire files in RAM.
- **Atomic in-place updates**: Writes to a temporary `.tmp` file and renames it, avoiding partial writes.
- **Authenticated format**: Includes a 5-byte magic header and version byte for compatibility checks.
- **Strict key enforcement**: Requires a fixed-length 32 B key file (`key.key`), exiting if missing or invalid.
- **Minimal dependencies**: Uses `clap` for CLI parsing and `sodiumoxide` (bundled) for cryptography.

---

## Requirements

- Rust 2024 edition toolchain
- A 32-byte random key file named `key.key`, placed in the working directory
- **Bundled**: No external `libsodium` library required
- **Optional (system libsodium)**: If you disable the bundled feature, install your platform’s `libsodium` development package (e.g., `libsodium-dev` on Linux) for linking.

---

## Installation

### Bundled (default)

`filecrypt` will compile and link its own snapshot of `libsodium`. No additional steps are necessary:

```bash
cargo build --release
```

or install globally:

```bash
cargo install --path .
```

### Using system libsodium (optional)

If you prefer to link against your system’s `libsodium`:

1. Install the development package:
   ```bash
   # Debian/Ubuntu
   sudo apt-get install libsodium-dev
   # Fedora/CentOS
   sudo dnf install libsodium-devel
   ```
2. Build as usual:
   ```bash
   cargo build --release
   ```

---

## Key Generation

Generate a strong random key once and keep it safe. This 32 B key is the only secret your tool needs:

```bash
head -c 32 /dev/urandom > key.key
chmod 600 key.key
```

The tool will refuse to run if `key.key` is missing or not exactly 32 bytes, printing an error message indicating the required length.

---

## Usage

```bash
# Encrypt in-place:
filecrypt E <filename>

# Decrypt in-place:
filecrypt D <filename>
```

- `E` and `D` are subcommands (replacing the previous long names `encrypt`/`decrypt`).
- The tool reads `key.key`, processes the target file in 64 KiB chunks, and atomically overwrites it.

**Examples**:

```bash
# Encrypt notes.txt
./target/release/filecrypt E notes.txt

# Decrypt notes.txt
./filecrypt D notes.txt
```

---

## File Format

Encrypted files follow this layout:

```
0      5      6        7+                    ...
+------+-----+--------+-------------------------------
| MAGIC|VER  | HEADER | CHUNK_1 || CHUNK_2 || ... || TAG_FINAL |
+------+-----+--------+-------------------------------
```

- **MAGIC** (5 bytes): `MYENC` — identifies the format.
- **VER** (1 byte): Version number (currently `1`).
- **HEADER** (24 bytes): SecretStream header, carrying initial state.
- **CHUNK_n**: Each chunk is the ciphertext of a 64 KiB plaintext slice, tagged (`Message` or `Final`).

This assures both confidentiality and integrity, detecting any tampering or truncation.

---

## Security Considerations

- **AEAD (XChaCha20-Poly1305)**: Provides encryption and authentication with 192-bit nonces, preventing nonce reuse even across large message spaces.
- **Chunked streaming**: Protects against memory exhaustion and enables partial reads if needed.
- **Atomic writes**: Prevents data loss on crashes by only replacing the original file once the write completes.
- **Key safety**: Store `key.key` securely (`chmod 600`), and rotate periodically if desired.
- **Zeroization**: Consider linking with the `zeroize` crate to wipe secrets from RAM after use.

---

## Contributing

1. Fork the repo.
2. Create a feature branch (`git checkout -b feature/YourChange`).
3. Commit your changes and open a Pull Request.
4. Ensure all CI checks pass and tests (if any) are added.

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

