"""
=============================================================
  SECURE CODING REVIEW PROJECT — Secure Login System
  File   : login_secure.py
  Purpose: Fixed, production-ready version of the login app
  Author : College Mini Project
=============================================================

  FIXES APPLIED IN THIS FILE:
  [1] SQL Injection        → Parameterized queries
  [2] Plain-text Passwords → bcrypt hashing
  [3] Weak MD5 Hashing     → bcrypt.checkpw()
  [4] Hardcoded Secrets    → os.getenv() + .env file
  [5] Error Leakage       → logging module + generic msg

  INSTALL DEPENDENCIES FIRST:
      pip install bcrypt python-dotenv
=============================================================
"""

import sqlite3
import bcrypt
import logging
import os
from dotenv import load_dotenv

# ─────────────────────────────────────────────────────────
# FIX 4 — Load secrets from environment / .env file
# Create a .env file in the same folder with:
#   SECRET_KEY=your_long_random_secret_here
#   DB_PATH=users.db
# Then add .env to your .gitignore — never commit it!
# ─────────────────────────────────────────────────────────
load_dotenv()  # Reads the .env file silently

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")  # ✅ From env
DB_PATH    = os.getenv("DB_PATH", "users_secure.db")             # ✅ Configurable


# ─────────────────────────────────────────────────────────
# FIX 5 — Structured logging instead of print(error)
# Errors are written to app.log (private to the server).
# Users only ever see a generic "something went wrong" msg.
# ─────────────────────────────────────────────────────────
logging.basicConfig(
    filename="app.log",
    level=logging.WARNING,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


# ─────────────────────────────────────────────────────────
# Helper — Input validation
# ─────────────────────────────────────────────────────────
def is_valid_username(username: str) -> bool:
    """
    Allow only alphanumeric usernames between 3 and 32 chars.
    Reject inputs that contain special characters, preventing
    a first line of defense even before the DB query.
    """
    if not username or not (3 <= len(username) <= 32):
        return False
    return username.isalnum()


def setup_database():
    """
    Create the users table and insert a sample admin user.
    The password is HASHED with bcrypt before storage.
    """
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY,
            username      TEXT    UNIQUE NOT NULL,
            password_hash TEXT    NOT NULL
        )
    """)

    # ─────────────────────────────────────────────────────
    # FIX 2 & 3 — bcrypt hashing with automatic salt
    # bcrypt.gensalt() generates a unique random salt every
    # call.  Even if two users pick the same password, their
    # hashes will be completely different.
    # bcrypt is intentionally SLOW (~100 ms), making brute
    # force attacks impractical.
    # ─────────────────────────────────────────────────────
    hashed_password = bcrypt.hashpw(b"password123", bcrypt.gensalt())  # ✅

    # ─────────────────────────────────────────────────────
    # FIX 1 — Parameterized query (? placeholders)
    # SQLite treats every ? value as pure data, never as SQL
    # syntax.  Injection attacks are structurally impossible.
    # ─────────────────────────────────────────────────────
    cursor.execute(
        "INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)",
        (1, "admin", hashed_password),  # ✅ Tuple of parameters
    )

    conn.commit()
    conn.close()


def verify_password(plain_password: str, stored_hash: bytes) -> bool:
    """
    Safely compare a plain-text password against a bcrypt hash.
    bcrypt.checkpw() is timing-safe — it takes the same amount
    of time regardless of where the strings differ, preventing
    timing-based side-channel attacks.
    """
    return bcrypt.checkpw(plain_password.encode(), stored_hash)  # ✅


def login_user(username: str, plain_password: str) -> bool:
    """
    Authenticate a user securely.
    - Validates username format before touching the DB.
    - Uses a parameterized query (no SQL Injection).
    - Fetches only the password_hash, not the whole row.
    - Uses bcrypt to verify the password.
    """
    # Input validation gate
    if not is_valid_username(username):
        return False

    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ✅ Parameterized query — user input never touches SQL syntax
    cursor.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return False  # Username not found

    stored_hash = row[0]
    # stored_hash might be str (from DB) or bytes; ensure bytes
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode()

    return verify_password(plain_password, stored_hash)


def main():
    setup_database()

    print("=" * 40)
    print("    SECURE LOGIN SYSTEM (Demo)")
    print("=" * 40)

    username = input("Enter username: ")
    password = input("Enter password: ")

    try:
        if login_user(username, password):
            # Show only the username — never echo back the password
            print(f"\n✅ Login successful! Welcome, {username}")
        else:
            # Generic message — don't reveal whether username or
            # password was wrong (prevents username enumeration)
            print("\n❌ Login failed. Invalid credentials.")

    except Exception as e:
        # ✅ FIX 5: Log privately, tell user nothing useful to attackers
        logging.error("Login error for user '%s': %s", username, e)
        print("\n⚠  An unexpected error occurred. Please try again.")


if __name__ == "__main__":
    main()