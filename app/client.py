"""Client skeleton — plain TCP; no TLS. See assignment spec."""

# app/client.py
"""
SecureChat Client – Full CIANR, Fixed Auth Flow, Signed Transcript
"""

# app/client.py
import socket
import json
import base64
import getpass
import os

from app.crypto.pki import validate_server_certificate, extract_public_key_from_cert
from app.crypto.dh import client_dh_initiate, client_dh_finalize
from app.crypto.aes import encrypt_aes, decrypt_aes
from app.crypto.sign import sign_data, verify_signature
from app.common.protocol import (
    Hello, ServerHello, Register, Login, DHClient, DHServer, Message, Receipt
)
from app.common.utils import now_ms, b64e, b64d, sha256_hex

HOST = "127.0.0.1"
PORT = 9999
CA_PATH = "certs/MyRootCA_ca_cert.pem"
EXPECTED_SERVER = "myserver.example.com"
CLIENT_CERT_PATH = "certs/client.example.com_cert.pem"
CLIENT_KEY_PATH = "certs/client.example.com_key.pem"

def load_pem(path: str) -> str:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def send_json(sock: socket.socket, data: dict):
    msg = json.dumps(data).encode("utf-8")
    sock.sendall(len(msg).to_bytes(4, "big") + msg)

def recv_json(sock: socket.socket) -> dict:
    len_bytes = sock.recv(4)
    length = int.from_bytes(len_bytes, "big")
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Closed")
        data += chunk
    return json.loads(data.decode("utf-8"))

def main():
    client_cert = load_pem(CLIENT_CERT_PATH)
    client_key = load_pem(CLIENT_KEY_PATH)

    with socket.create_connection((HOST, PORT)) as sock:
        print("[CLIENT] Connected")

        hello = Hello(type="hello", timestamp=now_ms(), client_cert=client_cert)
        send_json(sock, hello.model_dump())
        server_hello_raw = recv_json(sock)
        server_hello = ServerHello(**server_hello_raw)
        validate_server_certificate(server_hello.server_cert, CA_PATH, EXPECTED_SERVER)
        print("[CLIENT] Server cert OK")

        while True:
            print("\n" + "="*30)
            print("WELCOME TO SECURE CHAT APP")
            print("="*30)
            choice = input("Press L for Login or R for Register: ").strip().upper()

            if choice == "R":
                username = input("Username: ")
                password = getpass.getpass("Password: ")
                pwd_hash = sha256_hex(password.encode())
                reg = Register(type="register", timestamp=now_ms(), username=username, password_hash=pwd_hash)
                send_json(sock, reg.model_dump())
                resp = recv_json(sock)
                print(f"[SERVER] {resp['type'].upper()}")
                if resp["type"] == "success":
                    print("You can now login.")
            elif choice == "L":
                username = input("Username: ")
                password = getpass.getpass("Password: ")
                pwd_hash = sha256_hex(password.encode())
                login = Login(type="login", timestamp=now_ms(), username=username, password_hash=pwd_hash)
                send_json(sock, login.model_dump())
                resp = recv_json(sock)
                if resp["type"] == "success":
                    print("[SERVER] Login success!")
                    break
                else:
                    print(f"[SERVER] Login failed: {resp.get('reason')}")
            else:
                print("Invalid choice.")

        # DH
        priv, dh_msg_raw = client_dh_initiate()
        dh_client = DHClient(**dh_msg_raw)
        send_json(sock, dh_client.model_dump())
        print("[CLIENT] Sent DH init")

        dh_server_raw = recv_json(sock)
        dh_server = DHServer(**dh_server_raw)
        aes_key = client_dh_finalize(priv, dh_server_raw)
        print("[CLIENT] AES key ready")

        print("\nChat started! Type 'I want to exit' to quit.")
        while True:
            text = input("[YOU] ")
            if text.strip().lower() == "i want to exit":
                ct = encrypt_aes(aes_key, text.encode())
                msg = Message(type="message", timestamp=now_ms(), sender="client", ciphertext=b64e(ct))
                msg_raw = msg.model_dump()
                sig = b64e(sign_data(client_key, json.dumps(msg_raw).encode()))
                send_json(sock, {**msg_raw, "signature": sig})
                break

            ct = encrypt_aes(aes_key, text.encode())
            msg = Message(type="message", timestamp=now_ms(), sender="client", ciphertext=b64e(ct))
            msg_raw = msg.model_dump()
            sig = b64e(sign_data(client_key, json.dumps(msg_raw).encode()))
            send_json(sock, {**msg_raw, "signature": sig})

            resp_raw = recv_json(sock)
            sig = b64d(resp_raw.pop("signature"))
            server_pub_key = extract_public_key_from_cert(server_hello.server_cert)
            if not verify_signature(server_pub_key, json.dumps(resp_raw).encode(), sig):
                print("[ERROR] Invalid server signature")
                break
            resp = Message(**resp_raw)
            pt = decrypt_aes(aes_key, b64d(resp.ciphertext)).decode("utf-8")
            print(f"[SERVER] {pt}")

        receipt_raw = recv_json(sock)
        receipt = Receipt(**receipt_raw)
        sig = b64d(receipt.signature)
        server_pub_key = extract_public_key_from_cert(server_hello.server_cert)  # FIXED
        if verify_signature(server_pub_key, receipt.transcript_hash.encode(), sig):
            print(f"[SERVER] Session closed. Transcript hash: {receipt.transcript_hash}")
        else:
            print("[ERROR] Invalid receipt")

if __name__ == "__main__":
    main()

# python -m app.client