#!/usr/bin/env python3

import base64
import hashlib
import os
import sys
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def normalize(name):
    return name.strip().lower().replace("-", "").replace("_", "").replace(" ", "")


def loading():
    frames = ["|", "/", "-", "\\"]
    end_time = time.time() + 1.5

    while time.time() < end_time:
        for frame in frames:
            sys.stdout.write(f"\rProcessing {frame}")
            sys.stdout.flush()
            time.sleep(0.1)

            if time.time() >= end_time:
                break

    sys.stdout.write("\r" + " " * 20 + "\r")
    sys.stdout.flush()


def aes_encrypt(text):
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)

    encrypted = AESGCM(key).encrypt(
        nonce,
        text.encode(),
        None
    )

    return (
        base64.b64encode(encrypted).decode(),
        base64.b64encode(key).decode(),
        base64.b64encode(nonce).decode()
    )


def aes_decrypt(ciphertext, key, nonce):
    encrypted = base64.b64decode(ciphertext)
    key = base64.b64decode(key)
    nonce = base64.b64decode(nonce)

    decrypted = AESGCM(key).decrypt(
        nonce,
        encrypted,
        None
    )

    return decrypted.decode("utf-8")


def chacha20_encrypt(text):
    key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)

    encrypted = ChaCha20Poly1305(key).encrypt(
        nonce,
        text.encode(),
        None
    )

    return (
        base64.b64encode(encrypted).decode(),
        base64.b64encode(key).decode(),
        base64.b64encode(nonce).decode()
    )


def chacha20_decrypt(ciphertext, key, nonce):
    encrypted = base64.b64decode(ciphertext)
    key = base64.b64decode(key)
    nonce = base64.b64decode(nonce)

    decrypted = ChaCha20Poly1305(key).decrypt(
        nonce,
        encrypted,
        None
    )

    return decrypted.decode("utf-8")


def rsa_encrypt(text):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    encrypted = public_key.encrypt(
        text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return (
        base64.b64encode(encrypted).decode(),
        private_pem.decode(),
        public_pem.decode()
    )


def rsa_decrypt(ciphertext, private_key):
    encrypted = base64.b64decode(ciphertext)

    private_key = serialization.load_pem_private_key(
        private_key.encode(),
        password=None
    )

    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted.decode("utf-8")


def hash_text(text, algorithm):
    data = text.encode()

    algorithms_map = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
        "sha3": hashlib.sha3_256,
        "sha3256": hashlib.sha3_256,
        "sha3512": hashlib.sha3_512,
        "blake2b": hashlib.blake2b,
        "blake2s": hashlib.blake2s,
    }

    if algorithm == "shake128":
        return hashlib.shake_128(data).hexdigest(32)

    if algorithm == "shake256":
        return hashlib.shake_256(data).hexdigest(64)

    func = algorithms_map.get(algorithm)

    if not func:
        raise ValueError("Unsupported hash algorithm.")

    return func(data).hexdigest()


def blake3_hash(text):
    try:
        import blake3
    except ImportError:
        raise RuntimeError("BLAKE3 requires: pip install blake3")

    return blake3.blake3(text.encode()).hexdigest()


def base58_encode(data):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    number = int.from_bytes(data, "big")

    if number == 0:
        return "1" if data else ""

    result = ""

    while number:
        number, remainder = divmod(number, 58)
        result = alphabet[remainder] + result

    padding_count = len(data) - len(data.lstrip(b"\0"))

    return "1" * padding_count + result


def base58_decode(text):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    number = 0

    for char in text:
        if char not in alphabet:
            raise ValueError("Invalid Base58 data.")

        number = number * 58 + alphabet.index(char)

    result = number.to_bytes(
        (number.bit_length() + 7) // 8,
        "big"
    )

    padding_count = len(text) - len(text.lstrip("1"))

    return b"\0" * padding_count + result


def encode_text(text, algorithm):
    data = text.encode()

    if algorithm == "base64":
        return base64.b64encode(data).decode()

    if algorithm == "base32":
        return base64.b32encode(data).decode()

    if algorithm == "base58":
        return base58_encode(data)

    if algorithm in ("hex", "hexadecimal"):
        return data.hex()

    raise ValueError("Unsupported encoding.")


def decode_text(text, algorithm):
    if algorithm == "base64":
        return base64.b64decode(text).decode("utf-8")

    if algorithm == "base32":
        return base64.b32decode(text).decode("utf-8")

    if algorithm == "base58":
        return base58_decode(text).decode("utf-8")

    if algorithm in ("hex", "hexadecimal"):
        return bytes.fromhex(text).decode("utf-8")

    raise ValueError("Unsupported encoding.")


def main():
    mode = input("Mode [Encrypt/Decrypt] > ").strip().lower()

    if mode not in ("encrypt", "decrypt"):
        print("Invalid mode.")
        return

    algorithm_input = input("Encryption type > ")
    algorithm = normalize(algorithm_input)

    if mode == "encrypt":
        text = input("Text > ")

        loading()

        try:
            if algorithm == "aes":
                encrypted, key, nonce = aes_encrypt(text)

                print("Encrypted text >")
                print(encrypted)

                print("\nKey >")
                print(key)

                print("\nNonce >")
                print(nonce)

            elif algorithm in ("chacha20", "chacha"):
                encrypted, key, nonce = chacha20_encrypt(text)

                print("Encrypted text >")
                print(encrypted)

                print("\nKey >")
                print(key)

                print("\nNonce >")
                print(nonce)

            elif algorithm == "rsa":
                encrypted, private_key, public_key = rsa_encrypt(text)

                print("Encrypted text >")
                print(encrypted)

                print("\nPrivate key >")
                print(private_key)

                print("Public key >")
                print(public_key)

            elif algorithm in (
                "md5",
                "sha1",
                "sha224",
                "sha256",
                "sha384",
                "sha512",
                "sha3",
                "sha3256",
                "sha3512",
                "shake128",
                "shake256",
                "blake2b",
                "blake2s"
            ):
                print("Hash >")
                print(hash_text(text, algorithm))

            elif algorithm == "blake3":
                print("Hash >")
                print(blake3_hash(text))

            elif algorithm in (
                "base64",
                "base32",
                "base58",
                "hex",
                "hexadecimal"
            ):
                print("Encoded text >")
                print(encode_text(text, algorithm))

            else:
                print("Unsupported type.")

        except Exception as error:
            print(f"Error > {error}")

    else:
        loading()

        try:
            if algorithm == "aes":
                ciphertext = input("Encrypted text > ")
                key = input("Key > ")
                nonce = input("Nonce > ")

                decrypted = aes_decrypt(
                    ciphertext,
                    key,
                    nonce
                )

                print("\nDecrypted text >")
                print(decrypted)

            elif algorithm in ("chacha20", "chacha"):
                ciphertext = input("Encrypted text > ")
                key = input("Key > ")
                nonce = input("Nonce > ")

                decrypted = chacha20_decrypt(
                    ciphertext,
                    key,
                    nonce
                )

                print("\nDecrypted text >")
                print(decrypted)

            elif algorithm == "rsa":
                ciphertext = input("Encrypted text > ")

                print("Paste the private key.")
                private_key = sys.stdin.read()

                decrypted = rsa_decrypt(
                    ciphertext,
                    private_key
                )

                print("\nDecrypted text >")
                print(decrypted)

            elif algorithm in (
                "base64",
                "base32",
                "base58",
                "hex",
                "hexadecimal"
            ):
                encoded = input("Encoded text > ")

                print("\nDecoded text >")
                print(decode_text(encoded, algorithm))

            elif algorithm in (
                "md5",
                "sha1",
                "sha224",
                "sha256",
                "sha384",
                "sha512",
                "sha3",
                "sha3256",
                "sha3512",
                "shake128",
                "shake256",
                "blake2b",
                "blake2s",
                "blake3"
            ):
                print("Hash algorithms cannot be decrypted.")

            else:
                print("Unsupported type.")

        except Exception as error:
            print(f"Decryption error > {error}")


if __name__ == "__main__":
    main()
