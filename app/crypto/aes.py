"""AES-128(ECB)+PKCS#7 helpers (use library).""" 
# raise NotImplementedError("students: implement AES helpers")

# app/crypto/aes.py
"""
AES-128-ECB with PKCS#7 padding.
Used in Data Plane for confidentiality.

Spec:
  - AES-128-ECB (block cipher)
  - PKCS#7 padding (pad to 16-byte blocks)
  - Input: plaintext bytes
  - Output: ciphertext bytes (base64 in JSON)
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

backend = default_backend()

BLOCK_SIZE = 16  # AES block size in bytes


def pkcs7_pad(data: bytes) -> bytes:
    """
    Add PKCS#7 padding to data.
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    Append pad_len bytes, each with value pad_len.
    """
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    padding = bytes([pad_len]) * pad_len
    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding.
    Raises ValueError if padding is invalid.
    """
    if len(data) == 0:
        raise ValueError("Zero-length data cannot be unpadded")
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("Data length must be multiple of block size")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]


def encrypt_aes(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128-ECB with PKCS#7 padding.
    key: 16 bytes (from dh.derive_aes_key)
    plaintext: raw bytes (e.g. b'Hello')
    Returns: ciphertext bytes
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")

    padded = pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return ct


def decrypt_aes(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128-ECB and remove PKCS#7 padding.
    Returns: plaintext bytes
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    pt_padded = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(pt_padded)


# ----------------------------------------------------------------------
# Test when run directly
# ----------------------------------------------------------------------
if __name__ == "__main__":
    from app.crypto.dh import client_dh_initiate, client_dh_finalize, generate_dh_pair, server_dh_respond

    # Simulate DH to get shared key
    client_priv, client_msg = client_dh_initiate()
    server_priv, _ = generate_dh_pair()
    server_key, server_resp = server_dh_respond(client_msg, server_priv)
    client_key = client_dh_finalize(client_priv, server_resp)

    assert server_key == client_key
    key = client_key

    # Test encryption/decryption
    msg = b"Hello, Secure Chat!"
    ct = encrypt_aes(key, msg)
    pt = decrypt_aes(key, ct)

    print(f"Original : {msg}")
    print(f"Ciphertext (hex): {ct.hex()}")
    print(f"Decrypted: {pt}")
    assert pt == msg
    print("AES-128-ECB + PKCS#7 test passed!")

# python -m app.crypto.aes