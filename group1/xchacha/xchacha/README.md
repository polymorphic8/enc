
# a simple command-line utility for encrypting or decrypting files using XChaCha20-Poly1305

It is not about the name! You can change the default name in Cargo.toml before you compile or simply rename the executable after it is compiled. 

A key is often better than a password. So should an encryption app use a password or key? I solved that question with a nice design choice. The app always relies on a key, but you can make the same key from the same password (deterministic key). Near the top of main.rs you can salt the key gen, so a password would made a different key for each salt! That is an awesome solution. You can use any third party app to make a 32 byte key file also. You can change the salt and the key name in main.rs before you compile. 

# Keygen
./chacha20_cli --keygen "mysecretpassword"   makes a key, or you can put a key in the same directory as the executable. 

# Encrypt or Decrypt a file. 

./chacha20_cli --E input.html out.html    

./chacha20_cli --D out.html decrypted.html



# Atomic In-Place Overwrite

./chacha20_cli --over api.html --E

./chacha20_cli --over api.html --D

That is it! This app has simple input commands but it can do a lot! It is an all in one encryption app solution! Key maker, password, no pasword, always uses a key, make another file or overwrite in place. That is a great set of features for a single encryption app! 

# Design choices 

XChaCha20-Poly1305 is WAY less complicated and easier to implement than AES is. So it is more reliable for apps like this. It is equal to AES in terms of strong encryption. There are many articles on AES vs XChaCha20-Poly1305 - and the latter has advantages. 
