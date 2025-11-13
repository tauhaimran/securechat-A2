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


def get_conn():
    """Return a MySQL connection."""
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
    """Register a new user with salted password."""
    salt = os.urandom(16)
    pwd_hash = hash_password(password, salt)
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, salt, pwd_hash) VALUES (%s, %s, %s)",
                    (username, salt, pwd_hash)
                )
        return True
    except pymysql.err.IntegrityError:
        return False  # username already exists


def verify_user(username: str, password: str) -> bool:
    """Verify login credentials."""
    conn = get_conn()
    with conn:
        with conn.cursor() as cur:
            cur.execute("SELECT salt, pwd_hash FROM users WHERE username=%s", (username,))
            row = cur.fetchone()
            if not row:
                return False
            salt = row["salt"]
            expected_hash = row["pwd_hash"]
            return hash_password(password, salt) == expected_hash


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