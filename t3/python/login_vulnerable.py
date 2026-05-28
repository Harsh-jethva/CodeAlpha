"""
=============================================================
  SECURE CODING REVIEW PROJECT — Vulnerable Login System
  File   : login_vulnerable.py
  Purpose: Intentionally insecure code for educational review
  Author : College Mini Project
=============================================================

  VULNERABILITIES PRESENT IN THIS FILE:
  [1] SQL Injection              — Line 47  (HIGH)
  [2] Plain-text Password Storage— Line 30  (HIGH)
  [3] Weak MD5 Hashing           — Line 37  (HIGH)
  [4] Hardcoded Credentials      — Line 22  (MEDIUM)
  [5] Verbose Error Leakage       — Line 58  (LOW)

  DO NOT use this code in any real application.
=============================================================
"""

import sqlite3
import hashlib

# ─────────────────────────────────────────────────────────
# VULNERABILITY 4 — Hardcoded Credentials / Secrets
# Problem : Sensitive values are written directly in code.
#           Anyone who reads or steals the source file gets
#           the secret key instantly.
# Fix     : Use environment variables (see login_secure.py)
# ─────────────────────────────────────────────────────────
SECRET_KEY = "admin123"       # ❌ Hardcoded secret key
DB_PATH    = "users.db"       # ❌ Hardcoded database path


def setup_database():
    """Create the users table and insert a sample user."""
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    """)

    # ─────────────────────────────────────────────────────
    # VULNERABILITY 2 — Plain-text Password Storage
    # Problem : The password 'password123' is stored exactly
    #           as typed.  A database breach reveals every
    #           user's real password immediately.
    # Fix     : Hash with bcrypt before storing.
    # ─────────────────────────────────────────────────────
    cursor.execute(
        "INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123')"
    )  # ❌ Plain-text password in database

    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────
# VULNERABILITY 3 — Weak MD5 Hashing
# Problem : MD5 was never designed for passwords.
#           It is extremely fast (billions/sec on a GPU) and
#           has no salt — two users with the same password
#           produce the SAME hash.  Rainbow-table attacks
#           crack common MD5 hashes in milliseconds.
# Fix     : Use bcrypt / scrypt / Argon2 instead.
# ─────────────────────────────────────────────────────────
def hash_password(password):
    """Hash a password using MD5 — insecure, for demo only."""
    return hashlib.md5(password.encode()).hexdigest()  # ❌ MD5 is broken


# ─────────────────────────────────────────────────────────
# VULNERABILITY 1 — SQL Injection
# Problem : User input is pasted directly into the SQL
#           string with an f-string.  An attacker can type:
#
#             username: admin' OR '1'='1' --
#             password: anything
#
#           The query becomes:
#             SELECT * FROM users
#             WHERE username = 'admin' OR '1'='1' --'
#             AND password = '...'
#
#           '1'='1' is always TRUE → login bypassed!
# Fix     : Use parameterized queries with ? placeholders.
# ─────────────────────────────────────────────────────────
def login_user(username, password):
    """Authenticate a user — vulnerable to SQL Injection."""
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ❌ Direct string interpolation — SQL Injection possible!
    query = (
        f"SELECT * FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result is not None


# ─────────────────────────────────────────────────────────
# VULNERABILITY 5 — Verbose Error / Information Leakage
# Problem : The raw exception message is printed to the
#           screen.  This can reveal database file paths,
#           table names, column names, or query structure —
#           valuable information for an attacker.
# Fix     : Log errors privately; show a generic message.
# ─────────────────────────────────────────────────────────
def main():
    setup_database()

    print("=" * 40)
    print("   VULNERABLE LOGIN SYSTEM (Demo)")
    print("=" * 40)

    username = input("Enter username: ")
    password = input("Enter password: ")

    try:
        if login_user(username, password):
            print(f"\n✅ Login successful! Welcome, {username}")
        else:
            print("\n❌ Login failed. Invalid username or password.")
    except Exception as e:
        # ❌ Leaks internal error details to the user!
        print(f"Database error: {e}")


if __name__ == "__main__":
    main()