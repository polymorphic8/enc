# Xcrypt XChaCha20-Poly1305 High security file encryption. 

VERY good app, lots of care went into it. This is made for LINUX to ensure that atomic file overwrite is reliable. (windows needs slightly different code)



usage ./Xcrypt [input file]

see /docs 

# Cryptographic Strength Comparison: AES-GCM, XChaCha20-Poly1305, and AES-GCM-SIV

Authenticated Encryption with Associated Data (AEAD) algorithms provide both confidentiality and integrity for data. This document compares three modern AEAD schemes in terms of their cryptographic strength and resistance to attacks. The schemes under consideration are:


1. **AES-GCM-SIV**
2. **XChaCha20-Poly1305**
3. **AES-GCM (AES in Galois/Counter Mode)**



Below, each algorithm is discussed in detail, covering the encryption process, key management, security features, and resistance to known attack vectors. Finally, a ranking is provided—from 1 (strongest) to 3 (least strong)—based on both theoretical strength and real-world security considerations.

---

## AES-GCM (AES in Galois/Counter Mode)

### Overview

AES-GCM combines the Advanced Encryption Standard (AES) block cipher in counter mode with the GHASH authentication algorithm to provide authenticated encryption. It is widely adopted (e.g., in TLS) for its performance and security, though it requires careful handling of nonces (initialization vectors).

- **Key sizes:** 128-, 192-, or 256-bit (commonly 128 or 256).
- **Authentication Tag:** Produces a 128-bit tag.

### Encryption Process

1. **Key & Nonce:**  
   - A single symmetric key is used.
   - A unique nonce (IV) – typically 96 bits – is chosen for each encryption.
   - **Critical:** Each nonce must be unique per key.

2. **AES-CTR Encryption:**  
   - The plaintext is encrypted using AES in counter mode.
   - AES produces a keystream by encrypting successive counter blocks (derived from the nonce) which is then XORed with the plaintext to form the ciphertext.

3. **GHASH Authentication:**  
   - Simultaneously, the GHASH function computes an authentication tag over the ciphertext and any Additional Authenticated Data (AAD).
   - GHASH is a polynomial hash in GF(2^128) using a hash subkey \(H = AES_K(0^{128})\).

4. **Tag Generation:**  
   - The final tag is formed by encrypting the GHASH output (or XORing it with an AES encryption of a nonce-derived block), resulting in a 128-bit authentication tag.
   - During decryption, the receiver recomputes GHASH and verifies the tag to ensure integrity and authenticity.

### Key Management

- **Nonce Management:** Nonces must be unique under a given key.  
- **IV Usage:** A typical 96-bit IV is used; when using random IVs, NIST recommends limiting the number of messages per key to avoid collisions.
- **Best Practice:** A counter-based IV scheme is often preferred to ensure uniqueness.  
- **Re-keying:** Keys should be rotated before theoretical usage limits are reached to maintain security.

### Security Features

- **Confidentiality & Integrity:** Provides strong encryption (AES) and integrity (GHASH) with a 128-bit tag.  
- **Forgery Resistance:** The probability of a successful forgery is approximately \(2^{-128}\).
- **Performance:** Optimized on modern CPUs with AES-NI and PCLMULQDQ for fast AES and GHASH operations.
- **Standardization:** Defined in NIST SP 800-38D and widely deployed, provided nonces are unique and implementations are constant-time.

### Resistance to Attacks

- **Nonce Misuse:** Reusing a nonce with the same key can expose relationships between plaintexts and lead to forgery attacks.
- **Side-Channel Attacks:** Must be implemented in constant-time to avoid leakage via cache-timing attacks.
- **Theoretical Attacks:** No attacks better than brute force are known when nonces are unique.

### Summary

AES-GCM is extremely secure when implemented correctly, but its heavy reliance on unique nonces makes it vulnerable if nonce management is mishandled.

---

## XChaCha20-Poly1305

### Overview

XChaCha20-Poly1305 is an extended-nonce variant of ChaCha20-Poly1305, using a 192-bit nonce instead of 96 bits. It employs the 256-bit ChaCha20 stream cipher along with the Poly1305 MAC, offering strong security and excellent resistance to side-channel attacks.

- **Key Size:** 256-bit.
- **Nonce:** 192-bit, allowing random generation without practical collision concerns.

### Encryption Process

1. **Key & Nonce:**  
   - Uses a 256-bit key and a 192-bit nonce.
   - The extended nonce minimizes collision risks.

2. **Subkey Derivation (HChaCha20):**  
   - Derives a one-time subkey from the main key and the first 128 bits of the nonce using HChaCha20.

3. **ChaCha20 Stream Encryption:**  
   - The subkey, along with the remaining 64 bits of the nonce and a 32-bit block counter, is input into ChaCha20 to produce a keystream.
   - The plaintext is XORed with this keystream to form the ciphertext.

4. **Poly1305 Authentication:**  
   - A one-time Poly1305 key is generated (typically from the first 64 bytes of the ChaCha20 keystream).
   - The ciphertext and any AAD are authenticated to produce a 128-bit tag.

### Key Management

- **Nonce Flexibility:** The 192-bit nonce enables random nonce generation with negligible risk of collisions.
- **Key Reuse:** The same key can safely encrypt a very large number of messages.
- **High Security Margin:** The use of a 256-bit key ensures a robust security margin.

### Security Features

- **Confidentiality & Integrity:** The ChaCha20 cipher and Poly1305 MAC provide strong protection.
- **Side-Channel Resistance:** Constant-time operations (add-rotate-xor) help resist cache-timing attacks.
- **Extended Nonce:** The large nonce space virtually eliminates accidental nonce reuse.

### Resistance to Attacks

- **Nonce Misuse:** While reuse of a nonce can be dangerous, the 192-bit nonce makes accidental reuse extremely unlikely.
- **Forgery Resistance:** Poly1305’s design ensures robust protection, provided each one-time key is unique.
- **Real-World Adoption:** Widely supported in protocols like WireGuard and TLS 1.3, and endorsed in libraries such as libsodium.

### Summary

XChaCha20-Poly1305 offers high security and excellent resistance to side-channel attacks, with its extended nonce space providing substantial practical safeguards against nonce reuse.

---

## AES-GCM-SIV

### Overview

AES-GCM-SIV is a variant designed to be nonce misuse-resistant, meaning that even if a nonce is accidentally reused, it does not catastrophically compromise confidentiality or integrity. It achieves this by combining AES-CTR with an internal polynomial hash (POLYVAL) and a synthetic IV.

- **Key Sizes:** 128 or 256-bit.
- **Nonce:** Typically 96-bit, similar to AES-GCM.
- **Primary Benefit:** Provides a safety net against nonce reuse.

### Encryption Process

1. **Keys and Nonce:**  
   - Uses a single master key with a 96-bit nonce.
   - Internally derives message-specific subkeys for each nonce.

2. **Subkey Derivation:**  
   - The master key and nonce generate an AES encryption subkey and a POLYVAL authentication subkey.

3. **POLYVAL Hash (Synthetic IV Generation):**  
   - Computes a polynomial hash over the plaintext and AAD.
   - Combines the hash value with the nonce to produce a synthetic IV.

4. **AES-CTR Encryption:**  
   - Encrypts the plaintext using AES-CTR with the synthetic IV as the starting counter.
   - The ciphertext is generated by XORing the plaintext with the AES keystream.

5. **Tag Generation (SIV Tag):**  
   - Encrypts the synthetic IV with the AES subkey to produce the final 128-bit authentication tag.
   - The tag is appended to the ciphertext.

### Key Management

- **Nonce Misuse Resistance:** Even if a nonce is reused, the system only reveals whether the same plaintext was used, without compromising the key.
- **Automatic Subkey Derivation:** Each message automatically generates unique subkeys, allowing safe encryption under one master key.
- **Recommendation:** Although tolerant of nonce reuse, standard best practices still advise against it.

### Security Features

- **Misuse Resistance:** Robust against nonce reuse—only identical plaintexts under a reused nonce will reveal repetition.
- **Strong AEAD Security:** Leverages AES and POLYVAL, both well-studied cryptographic primitives.
- **Efficiency:** While slightly slower than AES-GCM, it remains efficient with hardware acceleration.
- **Simplified Key Management:** Automatic subkey generation simplifies the overall key management process.

### Resistance to Attacks

- **Nonce Reuse:** Degrades gracefully by only indicating if the same plaintext was encrypted, without revealing further information.
- **Cryptanalytic Strength:** No feasible attacks are known against its underlying components (AES and POLYVAL).
- **Forgery Resistance:** The 128-bit SIV tag offers robust resistance to forgery attempts.
- **Implementation Considerations:** As with AES-GCM, constant-time implementations and hardware support are recommended.

### Summary

AES-GCM-SIV’s inherent resistance to nonce misuse makes it one of the most robust AEAD modes available. It effectively provides "AES-GCM with a safety net," making it an excellent choice in environments where nonce management errors might occur.

---

## Conclusion: Overall Ranking

Based on both theoretical security and real-world resilience (considering nonce misuse, side-channel resistance, and key management pitfalls), the algorithms are ranked as follows:

1. **AES-GCM-SIV – Most Robust**  
   - Provides strong nonce misuse resistance: even if a nonce is reused accidentally, the impact is minimized.
   - Built on solid cryptographic primitives (AES and POLYVAL).
   - Although newer and less widespread than AES-GCM, it is arguably the strongest option for practical deployments.

2. **XChaCha20-Poly1305 – Highly Secure**  
   - Uses a 256-bit cipher with an extended 192-bit nonce, virtually eliminating accidental nonce collisions.
   - Offers excellent resistance to side-channel attacks.
   - While it lacks formal misuse resistance, the extended nonce space makes accidental reuse extremely unlikely.

3. **AES-GCM – Strong but Less Forgiving**  
   - Cryptographically robust and fast when used correctly.
   - Highly sensitive to nonce reuse, where any mistake in nonce management can be catastrophic.
   - Widely implemented and trusted, yet its fragility in the event of nonce reuse places it behind the other two modes.

**Final Note:**  
All three algorithms are secure when implemented correctly with proper nonce and key management. However, in real-world scenarios where misuse might occur, AES-GCM-SIV and XChaCha20-Poly1305 provide greater resilience compared to AES-GCM.

---
