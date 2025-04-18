# XChaCha20‑Poly1305 File Encryption CLI

A pure‑Rust command‑line tool to encrypt or decrypt a file in place using XChaCha20‑Poly1305 AEAD for confidentiality and integrity.

---

## 📦 Usage

```bash
# Encrypt (first time, no header present)
a.exe secret.key myfile.txt

# Decrypt (magic header detected)
a.exe secret.key myfile.txt
```

- **secret.key** – 32‑byte binary key file  
- **myfile.txt** – file to encrypt or decrypt  

After running, `myfile.txt` will be atomically replaced by its encrypted or decrypted form.

---

## 🔍 How It Works

### 1. Magic Header & Atomic Replace
- Each encrypted file begins with a 4‑byte magic marker `XCP1` and a version byte.
- On startup, the tool reads the first 4 bytes:
  - If they match `XCP1`, it enters **decrypt** mode.
  - Otherwise, it enters **encrypt** mode.
- All output is written to `myfile.txt.tmp`, then renamed over the original to avoid partial writes.

### 2. Secure Nonce Generation (RNG)
- **Unix**: reads 24 random bytes from `/dev/urandom`.
- **Windows**: calls `BCryptGenRandom` from `bcrypt.dll`.
- A fresh 24‑byte nonce is generated **once per file** and written in the header.

### 3. XChaCha20 & HChaCha20
1. Split the 24‑byte nonce into:
   - 16‑byte input for **HChaCha20**  
   - 8‑byte “tail”  
2. Run **HChaCha20** (10 double‑rounds) to derive a 32‑byte subkey.  
3. Build a 12‑byte ChaCha20 nonce (4 zero bytes + 8‑byte tail).  
4. Use the subkey + ChaCha20 to generate a keystream:
   - **Block 0** produces the one‑time Poly1305 key.
   - **Blocks 1…** encrypt the data.

### 4. Poly1305 Authentication
- Constructs MAC data as:
  ```
  AAD ‖ ciphertext ‖ padding ‖ len(AAD) ‖ len(ciphertext)
  ```
- Uses 128‑bit arithmetic mod (2¹²⁸−5), with clamping of the r‑parameter.
- Tag ensures both authenticity and integrity of the ciphertext (and optional AAD).

### 5. AEAD Abstraction
Provided by the `XChaCha20Poly1305` struct:

- `encrypt_chunk(nonce, plaintext, aad) → (ciphertext, tag)`  
- `decrypt_chunk(nonce, ciphertext, aad, tag) → plaintext or error`

Counter starts at 1 when encrypting data. Block 0 is reserved for Poly1305 key generation.

### 6. Chunked File I/O
- Data is processed in **64 KiB** chunks.
- **Encrypt**:
  1. Write header (magic + version + nonce).
  2. For each chunk: encrypt → write ciphertext → write 16‑byte tag → increment nonce.
- **Decrypt**:
  1. Read header.
  2. For each chunk: read `chunk_size + 16` bytes → split ciphertext/tag → verify tag → decrypt → write plaintext → increment nonce.

---

## 🔒 Security Notes

- All arithmetic is constant‑time; no data‑dependent branches.
- Rust’s `unsafe` is confined to the FFI RNG block only.
- Keys and sensitive buffers are zeroed or dropped promptly after use.
- No external crypto crates—everything is implemented in safe Rust.

---

## 🚀 Building

```bash
git clone https://…/xchacha20-poly1305-cli.git
cd xchacha20-poly1305-cli
cargo build --release
```

- On **Windows**, ensure `bcrypt.lib` is accessible for linking.
- On **Unix**, no extra dependencies are needed.

---

*© 2025 Pure‑Rust Crypto CLI*

