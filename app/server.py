"""Server skeleton — plain TCP; no TLS. See assignment spec."""

# app/server.py
import socket
import json
import base64
import os
import threading
import uuid

from app.crypto.pki import validate_client_certificate, extract_public_key_from_cert
from app.crypto.dh import generate_dh_pair, server_dh_respond
from app.crypto.aes import encrypt_aes, decrypt_aes
from app.crypto.sign import sign_data, verify_signature
from app.common.protocol import (
    Hello, ServerHello, Register, Login, DHClient, DHServer, Message, Receipt
)
from app.common.utils import now_ms, b64e, b64d
from app.storage.db import init_users_table, register_user, verify_user
from app.storage.transcript import append_message, compute_transcript_hash

HOST = "127.0.0.1"
PORT = 9999
CA_PATH = "certs/MyRootCA_ca_cert.pem"
SERVER_CERT_PATH = "certs/myserver.example.com_cert.pem"
SERVER_KEY_PATH = "certs/myserver.example.com_key.pem"

def load_pem(path: str) -> str:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def send_json(conn: socket.socket, data: dict):
    msg = json.dumps(data).encode("utf-8")
    conn.sendall(len(msg).to_bytes(4, "big") + msg)

def recv_json(conn: socket.socket) -> dict:
    len_bytes = conn.recv(4)
    length = int.from_bytes(len_bytes, "big")
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Closed")
        data += chunk
    return json.loads(data.decode("utf-8"))

def handle_client(conn: socket.socket, addr):
    session_id = str(uuid.uuid4())[:8]
    server_cert = load_pem(SERVER_CERT_PATH)
    server_key = load_pem(SERVER_KEY_PATH)

    try:
        # 1. Hello
        hello_raw = recv_json(conn)
        hello = Hello(**hello_raw)
        validate_client_certificate(hello.client_cert, CA_PATH)
        print(f"[SERVER] Client {addr} cert OK")

        server_hello = ServerHello(type="server_hello", timestamp=now_ms(), server_cert=server_cert)
        send_json(conn, server_hello.model_dump())
        print("[SERVER] Sent server hello")

        # 2. Auth Loop
        authenticated = False
        while not authenticated:
            auth_raw = recv_json(conn)
            if auth_raw["type"] == "register":
                reg = Register(**auth_raw)
                success = register_user(reg.username, reg.password_hash)
                resp = {"type": "success" if success else "failure", "reason": "User exists" if not success else ""}
                send_json(conn, resp)
                if not success:
                    continue
                print(f"[SERVER] Registered {reg.username}")
            elif auth_raw["type"] == "login":
                login = Login(**auth_raw)
                if verify_user(login.username, login.password_hash):
                    send_json(conn, {"type": "success"})
                    authenticated = True
                    print(f"[SERVER] Login OK: {login.username}")
                else:
                    send_json(conn, {"type": "failure", "reason": "Wrong credentials"})
                    continue
            else:
                send_json(conn, {"type": "failure", "reason": "Invalid"})
                continue

        # 3. DH
        dh_client_raw = recv_json(conn)
        dh_client = DHClient(**dh_client_raw)
        priv, _ = generate_dh_pair()
        aes_key, dh_server_raw = server_dh_respond(dh_client_raw, priv)
        dh_server = DHServer(**dh_server_raw)
        send_json(conn, dh_server.model_dump())
        print("[SERVER] DH completed")

        # 4. Chat
        print(f"[SERVER] Chat with {addr}. Type messages. 'exit' to end.")
        while True:
            msg_raw = recv_json(conn)
            if msg_raw["type"] != "message":
                continue

            sig = b64d(msg_raw.pop("signature"))
            client_pub_key = extract_public_key_from_cert(hello.client_cert)  # FIXED
            if not verify_signature(client_pub_key, json.dumps(msg_raw).encode(), sig):
                print("[ERROR] Invalid client signature")
                break

            msg = Message(**msg_raw)
            pt = decrypt_aes(aes_key, b64d(msg.ciphertext)).decode("utf-8")
            print(f"[CLIENT] {pt}")

            if pt.strip().lower() == "i want to exit":
                break

            append_message(session_id, "client", msg.ciphertext, b64e(sig))

            text = input("[SERVER] ")
            ct = encrypt_aes(aes_key, text.encode("utf-8"))
            ct_b64 = b64e(ct)
            reply_msg = Message(type="message", timestamp=now_ms(), sender="server", ciphertext=ct_b64)
            reply_raw = reply_msg.model_dump()
            signature = b64e(sign_data(server_key, json.dumps(reply_raw).encode()))
            send_json(conn, {**reply_raw, "signature": signature})
            append_message(session_id, "server", ct_b64, signature)

        # 5. Receipt
        transcript_hash = compute_transcript_hash(session_id)
        receipt = Receipt(
            type="receipt",
            timestamp=now_ms(),
            identity="server",
            transcript_hash=transcript_hash,
            signature=b64e(sign_data(server_key, transcript_hash.encode()))
        )
        send_json(conn, receipt.model_dump())
        print(f"[SERVER] Sent receipt: {transcript_hash}")

    except Exception as e:
        print(f"[SERVER] Error: {e}")
    finally:
        conn.close()
        print(f"[SERVER] Closed {addr}")

def main():
    init_users_table()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print("[SERVER] Listening on 127.0.0.1:9999")

        while True:
            conn, addr = s.accept()
            print(f"[SERVER] New client: {addr}")
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()

# python -m app.server