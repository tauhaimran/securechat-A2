"""Server skeleton — plain TCP; no TLS. See assignment spec."""

# def main():
#     raise NotImplementedError("students: implement server workflow")

# if __name__ == "__main__":
#     main()

# app/server.py
"""
Minimal server – cert → DH → AES test.
"""

import socket
import json
import base64
import os

from app.crypto.pki import validate_client_certificate
from app.crypto.dh import generate_dh_pair, server_dh_respond
from app.crypto.aes import encrypt_aes, decrypt_aes

# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------
HOST = "127.0.0.1"
PORT = 9999
CA_PATH = "certs/MyRootCA_ca_cert.pem"
SERVER_CERT_PATH = "certs/myserver.example.com_cert.pem"

# ----------------------------------------------------------------------
# JSON over TCP
# ----------------------------------------------------------------------
def send_json(conn: socket.socket, data: dict):
    msg = json.dumps(data).encode()
    conn.sendall(len(msg).to_bytes(4, "big") + msg)

def recv_json(conn: socket.socket) -> dict:
    length = int.from_bytes(conn.recv(4), "big")
    data = conn.recv(length)
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
    server_cert = load_pem(SERVER_CERT_PATH)

    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print("[SERVER] Listening...")

        conn, addr = s.accept()
        print(f"[SERVER] Client {addr}")

        # 1. Hello
        hello = recv_json(conn)
        validate_client_certificate(hello["client cert"], CA_PATH)
        send_json(conn, {"type": "server hello", "server cert": server_cert})
        print("[SERVER] Client cert VALID")

        # 2. DH
        dh_msg = recv_json(conn)
        priv, _ = generate_dh_pair()
        aes_key, dh_resp = server_dh_respond(dh_msg, priv)
        send_json(conn, dh_resp)
        print(f"[SERVER] AES key: {aes_key.hex()}")

        # 3. AES test
        test_msg = recv_json(conn)
        ct = base64.b64decode(test_msg["ct"])
        pt = decrypt_aes(aes_key, ct)
        print(f"[SERVER] Received: {pt.decode()}")

        echo = encrypt_aes(aes_key, b"ECHO: " + pt)
        send_json(conn, {"pt": base64.b64encode(echo).decode()})

        print("[SERVER] Test passed!")

if __name__ == "__main__":
    main()

# python -m app.server