"""Client skeleton — plain TCP; no TLS. See assignment spec."""

# def main():
#     raise NotImplementedError("students: implement client workflow")

# if __name__ == "__main__":
#     main()

# app/client.py
"""
Minimal client – cert → DH → AES test (ASCII only).
"""

import socket
import json
import base64
import os

from app.crypto.pki import validate_server_certificate
from app.crypto.dh import client_dh_initiate, client_dh_finalize
from app.crypto.aes import encrypt_aes, decrypt_aes

# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------
HOST = "127.0.0.1"
PORT = 9999
CA_PATH = "certs/MyRootCA_ca_cert.pem"
EXPECTED_SERVER = "myserver.example.com"
CLIENT_CERT_PATH = "certs/client.example.com_cert.pem"

# ----------------------------------------------------------------------
# JSON over TCP
# ----------------------------------------------------------------------
def send_json(sock: socket.socket, data: dict):
    msg = json.dumps(data).encode()
    sock.sendall(len(msg).to_bytes(4, "big") + msg)

def recv_json(sock: socket.socket) -> dict:
    length = int.from_bytes(sock.recv(4), "big")
    data = sock.recv(length)
    return json.loads(data.decode())

# ----------------------------------------------------------------------
# Load PEM
# ----------------------------------------------------------------------
def load_pem(path: str) -> str:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing cert: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    client_cert = load_pem(CLIENT_CERT_PATH)

    with socket.create_connection((HOST, PORT)) as sock:
        print("[CLIENT] Connected")

        # 1. Hello
        send_json(sock, {"type": "hello", "client cert": client_cert})
        server_hello = recv_json(sock)
        validate_server_certificate(
            server_hello["server cert"],
            CA_PATH,
            EXPECTED_SERVER
        )
        print("[CLIENT] Server cert VALID")

        # 2. DH
        priv, dh_msg = client_dh_initiate()
        send_json(sock, dh_msg)
        dh_resp = recv_json(sock)
        aes_key = client_dh_finalize(priv, dh_resp)
        print(f"[CLIENT] AES key: {aes_key.hex()}")

        # 3. AES test – **ASCII ONLY**
        plaintext = b"HELLO FROM CLIENT - AES WORKS!"
        ct = encrypt_aes(aes_key, plaintext)
        send_json(sock, {"type": "aes_test", "ct": base64.b64encode(ct).decode()})

        resp = recv_json(sock)
        pt = decrypt_aes(aes_key, base64.b64decode(resp["pt"]))
        print(f"[CLIENT] Server echo: {pt.decode()}")

        print("\nTEST PASSED: PKI + DH + AES WORKING!")

if __name__ == "__main__":
    main()

# python -m app.client