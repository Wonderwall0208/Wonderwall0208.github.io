#!/usr/bin/env python3
"""
Encrypt a PDF for the Notes page (CLI alternative to encrypt-note.html).

Output layout matches notes.js exactly:
    [ salt: 16 ][ iv: 12 ][ ciphertext + GCM tag ]
KDF: PBKDF2-HMAC-SHA256, 200000 iterations -> AES-256-GCM.

Usage:
    python3 encrypt_note.py input.pdf notes/output.enc
    (you will be prompted for the password)
"""
import os
import sys
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITERATIONS = 200000


def encrypt(in_path: str, out_path: str, password: str) -> None:
    with open(in_path, "rb") as f:
        data = f.read()
    salt = os.urandom(16)
    iv = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))
    ct = AESGCM(key).encrypt(iv, data, None)  # ciphertext includes 16-byte tag at the end
    with open(out_path, "wb") as f:
        f.write(salt + iv + ct)
    print(f"Encrypted {in_path} -> {out_path} ({len(salt + iv + ct)} bytes)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    pw = os.environ.get("NOTE_PASSWORD") or getpass.getpass("Password: ")
    encrypt(sys.argv[1], sys.argv[2], pw)
