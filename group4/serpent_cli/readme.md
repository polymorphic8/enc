# Serpent CLI

**Serpent CLI** is a command-line tool that provides Serpent‑256 encryption and decryption with authentication (HMAC‑SHA256), using CBC mode with PKCS#7 padding and atomic file overwrite.

---

## Installation

```bash
git clone <repo-url>
cd serpent_cli
cargo build --release
```

---

## Key Setup

Place a `key.key` file (exactly 32 bytes, raw binary) in the same directory as the binary. The tool will exit if this file is missing or not 32 bytes long.

---

## Usage & Flags

```bash
serpent_cli [--encrypt -e | --decrypt -d] -p <paths...>
```

- `-e`, `--encrypt`  
  Encrypt the specified file(s) or directory(ies).
- `-d`, `--decrypt`  
  Decrypt the specified file(s) or directory(ies).
- `-p <paths...>`  
  One or more paths to files or directories to process.

---

## Encryption Process

1. Load a 256‑bit key from `key.key`.  
2. Derive a separate 256‑bit HMAC key by computing `HMACKey = SHA256(key)`.  
3. For each file:
   - Generate a random 16‑byte IV.
   - Apply PKCS#7 padding to the plaintext.
   - Encrypt in CBC mode with Serpent‑256.
   - Compute HMAC‑SHA256 over `IV ∥ ciphertext`.
   - Write out `IV ∥ ciphertext ∥ HMAC` to a temporary file, then atomically rename it.
4. For decryption:
   - Read `IV ∥ ciphertext ∥ HMAC` from the file.
   - Verify HMAC first (fail if mismatch).
   - Decrypt with Serpent‑CBC.
   - Strip PKCS#7 padding to recover the original plaintext.

---

## Security Comparison

| Aspect              | Serpent‑256                                                                 | AES‑256                                                     |
|---------------------|------------------------------------------------------------------------------|-------------------------------------------------------------|
| **Security margin** | 32 rounds, highly conservative; no practical attacks faster than brute‑force | 14 rounds; minor academic reduced‑round attacks but none practical |
| **Block size**      | 128 bits                                                                     | 128 bits                                                    |
| **Performance**     | Pure software; generally slower on modern CPUs                               | Hardware‑accelerated on AES‑NI enabled CPUs; faster throughput |
| **Maturity**        | Finalist in AES competition; less ubiquitous ecosystem support               | Ubiquitous in TLS, hardware, libraries, and standards       |

In theory, Serpent‑256 provides a larger safety margin, while AES‑256 benefits from hardware acceleration and widespread adoption.

---

## Atomic Overwrite

All file writes are atomic: data is written to a `.tmp` file first, then the original file is replaced via `rename`. This prevents partial or corrupted output if the process is interrupted.

---

## Example

Encrypt a single file:

```bash
serpent_cli -e -p a.txt
```

Decrypt it:

```bash
serpent_cli -d -p a.txt
```

---

## License

Specify your license here (e.g., MIT, Apache‑2.0).

