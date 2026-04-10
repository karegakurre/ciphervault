"""
cipher.py — Mode operasi CBC + padding PKCS#7 + derivasi kunci dari password
Menggunakan aes_core.py (tanpa library kriptografi eksternal).
"""

import os
import struct
import hashlib
from aes_core import aes_encrypt_block, aes_decrypt_block, key_expansion


# ─── Derivasi Kunci dari Password ─────────────────────────────────────────────
# Menggunakan PBKDF2 dengan SHA-256 (hanya hashlib — stdlib Python, bukan lib kriptografi)

def derive_key(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """Hasilkan 16-byte AES key dari password menggunakan PBKDF2-SHA256."""
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=16)
    return dk


# ─── Padding PKCS#7 ───────────────────────────────────────────────────────────

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Padding tidak valid — data rusak atau kunci salah.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding tidak valid — data rusak atau kunci salah.")
    return data[:-pad_len]


# ─── Mode CBC ─────────────────────────────────────────────────────────────────

def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Enkripsi CBC: setiap blok di-XOR dengan ciphertext blok sebelumnya."""
    padded   = pkcs7_pad(plaintext)
    round_keys = key_expansion(key)
    prev     = iv
    cipher   = bytearray()
    for i in range(0, len(padded), 16):
        block  = bytes(padded[i:i+16])
        xored  = bytes(a ^ b for a, b in zip(block, prev))
        enc    = aes_encrypt_block(xored, round_keys)
        cipher.extend(enc)
        prev   = enc
    return bytes(cipher)


def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Dekripsi CBC."""
    round_keys = key_expansion(key)
    prev       = iv
    plain      = bytearray()
    for i in range(0, len(ciphertext), 16):
        block = bytes(ciphertext[i:i+16])
        dec   = aes_decrypt_block(block, round_keys)
        plain.extend(a ^ b for a, b in zip(dec, prev))
        prev  = block
    return pkcs7_unpad(bytes(plain))


# ─── Antarmuka Tingkat Tinggi ──────────────────────────────────────────────────
# Format output: [4B magic][16B salt][16B IV][N*16B ciphertext]

MAGIC = b"AESCBC"

def encrypt(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    iv   = os.urandom(16)
    key  = derive_key(password, salt)
    ct   = cbc_encrypt(data, key, iv)
    return MAGIC + salt + iv + ct


def decrypt(blob: bytes, password: str) -> bytes:
    if not blob.startswith(MAGIC):
        raise ValueError("File bukan output enkripsi yang valid.")
    offset = len(MAGIC)
    salt   = blob[offset:offset+16]
    iv     = blob[offset+16:offset+32]
    ct     = blob[offset+32:]
    key    = derive_key(password, salt)
    return cbc_decrypt(ct, key, iv)
