# Keygen32


Keygen32 is a Rust CLI app that generates a deterministic 32-byte key from a given password. It uses the Argon2 (Argon2id variant) key derivation function and two compile-time “seed” strings, ensuring that the same password always produces the same key for a given set of seeds. By changing these seeds and recompiling, the same password will yield an entirely different 32-byte key. 
