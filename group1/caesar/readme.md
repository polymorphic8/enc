# Caesar Cipher CLI Application

## Overview
This is a simple command-line application written in Rust that encrypts text using a Caesar cipher with a shift of 3 characters. It handles both uppercase and lowercase letters, preserves spaces, and replaces unsupported characters with a placeholder (`�`).

## Features
- Encrypts text using Caesar cipher (shift of 3).
- Handles uppercase and lowercase English letters.
- Preserves whitespace.
- Unknown characters are replaced with `�`.
- Continuous loop for repeated encryptions without restarting.

## Requirements
- Rust (stable version)

## Installation
1. Clone the repository:
```bash
git clone <repository-url>
```

2. Navigate into the directory:
```bash
cd caesar_cipher
```

3. Build the application:
```bash
cargo build --release
```

## Usage
Run the compiled binary directly:
```bash
./target/release/caesar_cipher
```

Enter text directly into the console. The encrypted output is displayed instantly. To stop the application, press `Ctrl+C`.

### Example
Input:
```
Hello World!
```

Output:
```
Khoor Zruog�
```

## License
This project is provided under the MIT License. See [LICENSE](LICENSE) for more details.

