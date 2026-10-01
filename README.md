# CryptoTools

a lightweight Python CLI toolkit for encryption, hashing, and encoding

## Features

### Encryption

* AES-256-GCM
* ChaCha20-Poly1305
* RSA-2048 / OAEP

### Hashing

* MD5
* SHA-1
* SHA-224
* SHA-256
* SHA-384
* SHA-512
* SHA3-256 / SHA3-512
* SHAKE128 / SHAKE256
* BLAKE2b / BLAKE2s
* BLAKE3

### Encoding

* Base16 / Hex
* Base32
* Base58
* Base64

## Requirements

* Python 3.9+
* `cryptography`
* `blake3`

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/CryptoTools.git
cd CryptoTools
pip install -r requirements.txt
```

## USAGE

```bash
python3 main.py
```

example:

```text
Mode [Encrypt/Decrypt] > Encrypt
Encryption type > AES
Text > Hello World

Encrypted text >
...

Key >
...

Nonce >
...
```

The CLI supports both encryption/decryption and hashing/encoding operations.

## Security Notes

* MD5 and SHA-1 are included for educational and compatibility purposes.
* Base32, Base58, Base64 and Hex are encodings, not encryption.
* Never share or commit generated private keys or encryption keys.
* This project has not been designed as a replacement for audited production cryptographic software.

## Roadmap

* [ ] File encryption
* [ ] File hashing
* [ ] Hybrid encryption
* [ ] Digital signatures
* [ ] Automated tests
* [ ] CLI arguments

## License

See [LICENSE](LICENSE).

---

**Latent**
