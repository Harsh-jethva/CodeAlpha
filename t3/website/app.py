import hashlib
import logging
import os
import sqlite3

import bcrypt
from dotenv import load_dotenv
from flask import Flask, render_template, request


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-me-in-production")

SECURE_DB_PATH = os.getenv("DB_PATH", "users_secure.db")
VULNERABLE_DB_PATH = os.getenv("VULNERABLE_DB_PATH", "users_vulnerable.db")

logging.basicConfig(
    filename="app.log",
    level=logging.WARNING,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def is_valid_username(username: str) -> bool:
    if not username or not (3 <= len(username) <= 32):
        return False
    return username.isalnum()


def hash_md5(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def init_vulnerable_database() -> None:
    conn = sqlite3.connect(VULNERABLE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password_plain TEXT,
            password_md5 TEXT
        )
        """
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users (id, username, password_plain, password_md5) VALUES (?, ?, ?, ?)",
        (1, "admin", "password123", hash_md5("password123")),
    )
    conn.commit()
    conn.close()


def init_secure_database() -> None:
    conn = sqlite3.connect(SECURE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )

    hashed_password = bcrypt.hashpw(b"password123", bcrypt.gensalt())
    cursor.execute(
        "INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?)",
        (1, "admin", hashed_password),
    )
    conn.commit()
    conn.close()


def login_vulnerable(username: str, password: str) -> bool:
    conn = sqlite3.connect(VULNERABLE_DB_PATH)
    cursor = conn.cursor()

    password_md5 = hash_md5(password)
    query = (
        f"SELECT * FROM users "
        f"WHERE username = '{username}' AND "
        f"(password_plain = '{password}' OR password_md5 = '{password_md5}')"
    )

    logging.warning(
        "Vulnerable login attempt user=%s password=%s query=%s",
        username,
        password,
        query,
    )

    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result is not None


def login_secure(username: str, password: str) -> bool:
    if not is_valid_username(username):
        return False

    conn = sqlite3.connect(SECURE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return False

    stored_hash = row[0]
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode()

    return bcrypt.checkpw(password.encode(), stored_hash)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/vulnerable", methods=["GET", "POST"])
def vulnerable_page():
    result = None
    success = False

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        try:
            success = login_vulnerable(username, password)
            result = (
                "Login successful. Vulnerable mode accepted your credentials."
                if success
                else "Login failed. Invalid username or password."
            )
        except Exception as exc:
            logging.error("Vulnerable web error for user '%s': %s", username, exc)
            result = f"Database error: {exc}"

    return render_template(
        "login.html",
        mode="vulnerable",
        title="Vulnerable Login Lab",
        subtitle="This page intentionally includes the insecure patterns for study.",
        result=result,
        success=success,
    )


@app.route("/secure", methods=["GET", "POST"])
def secure_page():
    result = None
    success = False

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        try:
            success = login_secure(username, password)
            result = (
                f"Login successful. Welcome, {username}."
                if success
                else "Login failed. Invalid credentials."
            )
        except Exception as exc:
            logging.error("Secure web error for user '%s': %s", username, exc)
            result = "An unexpected error occurred. Please try again."

    return render_template(
        "login.html",
        mode="secure",
        title="Secure Login Demo",
        subtitle="This page uses the fixed implementation with safer defaults.",
        result=result,
        success=success,
    )


if __name__ == "__main__":
    init_vulnerable_database()
    init_secure_database()
    app.run(debug=True)