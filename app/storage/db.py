#"""MySQL users table + salted hashing (no chat storage).""" 
#raise NotImplementedError("students: implement DB layer")

# app/storage/db.py
# pip install mysql-connector-python
import mysql.connector
import os
import hashlib
import pymysql
from dotenv import load_dotenv

# Load environment variables for DB connection
load_dotenv()

DB_HOST = os.getenv("MYSQL_HOST", "localhost")
DB_USER = os.getenv("MYSQL_USER", "root")
DB_PASS = os.getenv("MYSQL_PASS", "")
DB_NAME = os.getenv("MYSQL_DB", "securechat")

# PURPOSE: Simple user storage + password hashing for the assignment.
# - Stores: username, 16-byte random salt (VARBINARY), SHA-256(salt||password) as hex.
# - This module is intentionally minimal (no password stretching) to keep the
#   assignment focused on integration with other components.


def get_conn():
    """Return a MySQL connection."""
    # create a new connection to the configured MySQL server
    # Caller is responsible for closing the connection (we use `with conn:` in helpers)
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )


def init_users_table():
    """Create the users table if it does not exist."""
    conn = get_conn()
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    salt VARBINARY(16) NOT NULL,
                    pwd_hash CHAR(64) NOT NULL
                )
            """)
    print("[DB] Users table ready.")


def hash_password(password: str, salt: bytes) -> str:
    """Return SHA-256 hash of salt+password as hex string."""
    return hashlib.sha256(salt + password.encode()).hexdigest()


def register_user(username: str, password: str) -> bool:
    """
    Create a new user record with a random 16-byte salt and SHA-256(salt||password).

    Returns True on success, False if the username already exists or on error.
    """
    # 1) Generate a cryptographically-random salt (16 bytes)
    salt = os.urandom(16)
    # 2) Compute password hash: SHA-256(salt || password)
    pwd_hash = hash_password(password, salt)

    # Debug output to help during development — print salt and hash (hex)
    print("\n--- REGISTER DEBUG ---")
    print("salt (hex)      =", salt.hex())
    print("pwd_hash        =", pwd_hash)
    print("----------------------\n")

    conn = get_conn()
    # Insert the new user into the database. We store the raw salt bytes (VARBINARY)
    # and the hex-encoded SHA-256 hash (CHAR(64)). Use parameterized query to avoid SQL injection.
    try:
        with conn:
            with conn.cursor() as cur:
                try:
                    cur.execute(
                        "INSERT INTO users (username, salt, pwd_hash) VALUES (%s, %s, %s)",
                        (username, salt, pwd_hash),
                    )
                    # ensure the INSERT is persisted
                    conn.commit()
                    return True
                except pymysql.err.IntegrityError:
                    # username UNIQUE constraint violated
                    print("DEBUG: user already exists")
                    return False
    except Exception as exc:  # pragma: no cover - unexpected DB error
        print("DEBUG: register error", exc)
        return False


def verify_user(username: str, password: str) -> bool:
    """
    Verify a username/password pair against the stored salt and hash.

    Steps:
    1. Load salt (VARBINARY) and expected hash (hex) from DB for the username.
    2. Convert salt to bytes (PyMySQL may return `bytearray` or `bytes`).
    3. Compute SHA-256(salt||password) and compare with stored hex string.
    """
    conn = get_conn()
    with conn:
        with conn.cursor() as cur:
            # fetch salt and stored hash for this user
            cur.execute("SELECT salt, pwd_hash FROM users WHERE username=%s", (username,))
            row = cur.fetchone()
            if not row:
                # no such user in DB
                print("DEBUG: user not found")
                return False

            raw_salt = row["salt"]
            expected = row["pwd_hash"]

            # PyMySQL may return `bytearray` or `bytes` for VARBINARY; normalize to bytes
            salt = bytes(raw_salt)

            # compute hash using same algorithm as registration
            computed = hash_password(password, salt)

            # helpful debug output during development
            print("\n--- LOGIN DEBUG ---")
            print("salt from DB (raw) =", raw_salt, type(raw_salt))
            print("salt converted     =", salt.hex())
            print("expected hash      =", expected)
            print("computed hash      =", computed)
            print("--------------------\n")

            return computed == expected

    





# ----------------------
# Driver/test code
# ----------------------
if __name__ == "__main__":
    init_users_table()
    print("Registering user 'alice' ->", register_user("alice", "mypassword"))
    print("Verify user 'alice' ->", verify_user("alice", "mypassword"))
    print("Verify wrong password ->", verify_user("alice", "wrongpass"))
#cli command examples:
# python app/storage/db.py 