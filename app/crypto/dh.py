"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation.""" 
# raise NotImplementedError("students: implement DH helpers")

# app/crypto/dh.py
"""
Diffie-Hellman key exchange + AES-128 key derivation.
Used in Key Agreement phase (post-authentication).

Spec:
  - Client sends: { "type":"dh client", "g": int, "p": int, "A": int }
  - Server sends: { "type":"dh server", "B": int }
  - Ks = A^b mod p = B^a mod p
  - K = Trunc16(SHA256(big-endian(Ks)))
"""

from typing import Tuple
import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from app.common.utils import now_ms  # ADD THIS

# ----------------------------------------------------------------------
# RFC 3526 2048-bit MODP Group (safe prime)
# ----------------------------------------------------------------------
P_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2

PARAMETERS = dh.DHParameterNumbers(P_2048, G).parameters(default_backend())


def generate_dh_pair() -> Tuple[dh.DHPrivateKey, dh.DHPublicKey]:
    private_key = PARAMETERS.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def get_dh_public_bytes(public_key: dh.DHPublicKey) -> int:
    return public_key.public_numbers().y


def compute_shared_secret(own_private_key: dh.DHPrivateKey, peer_public_value: int) -> bytes:
    peer_pub_numbers = dh.DHPublicNumbers(peer_public_value, PARAMETERS.parameter_numbers())
    peer_pub_key = peer_pub_numbers.public_key(default_backend())
    shared_key = own_private_key.exchange(peer_pub_key)
    return shared_key


def derive_aes_key(shared_secret: bytes) -> bytes:
    ks_int = int.from_bytes(shared_secret, "big")
    ks_bytes = ks_int.to_bytes((ks_int.bit_length() + 7) // 8, "big")
    digest = hashlib.sha256(ks_bytes).digest()
    return digest[:16]


# ----------------------------------------------------------------------
# CLIENT: INITIATE
# ----------------------------------------------------------------------
def client_dh_initiate() -> Tuple[dh.DHPrivateKey, dict]:
    priv, pub = generate_dh_pair()
    A = get_dh_public_bytes(pub)
    msg = {
        "type": "dh_client",           # MATCH protocol.py
        "timestamp": now_ms(),         # REQUIRED
        "p": str(P_2048),              # str for Pydantic
        "g": str(G),
        "A": str(A)
    }
    return priv, msg


# ----------------------------------------------------------------------
# SERVER: RESPOND
# ----------------------------------------------------------------------
def server_dh_respond(client_msg: dict, server_private_key: dh.DHPrivateKey) -> Tuple[bytes, dict]:
    A = int(client_msg["A"])
    if client_msg["p"] != str(P_2048) or client_msg["g"] != str(G):
        raise ValueError("DH parameters mismatch")

    server_pub = server_private_key.public_key()
    B = get_dh_public_bytes(server_pub)

    shared = compute_shared_secret(server_private_key, A)
    aes_key = derive_aes_key(shared)

    resp = {
        "type": "dh_server",           # MATCH protocol.py
        "timestamp": now_ms(),         # REQUIRED
        "B": str(B)
    }
    return aes_key, resp


# ----------------------------------------------------------------------
# CLIENT: FINALIZE
# ----------------------------------------------------------------------
def client_dh_finalize(client_private_key: dh.DHPrivateKey, server_msg: dict) -> bytes:
    B = int(server_msg["B"])
    shared = compute_shared_secret(client_private_key, B)
    return derive_aes_key(shared)


# ----------------------------------------------------------------------
# Test
# ----------------------------------------------------------------------
if __name__ == "__main__":
    client_priv, client_init = client_dh_initiate()
    print("Client →", client_init)

    server_priv, _ = generate_dh_pair()
    server_key, server_resp = server_dh_respond(client_init, server_priv)
    print("Server →", server_resp)

    client_key = client_dh_finalize(client_priv, server_resp)

    assert server_key == client_key, "DH key mismatch!"
    print("Shared AES-128 key:", client_key.hex())
    print("DH exchange successful!")

# python -m app.crypto.dh