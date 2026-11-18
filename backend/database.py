"""
QuantumShield Messenger - SQLite Database Management
Uses Write-Ahead Logging (WAL) for concurrent, high-integrity cryptographic persistence.
"""
import sqlite3
import os
import json
from datetime import datetime
from typing import List, Dict, Optional, Any

DB_FILE = os.path.join(os.path.dirname(__file__), "..", "quantumshield.db")


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """Initializes tables for users, encrypted messages, and security audit logs."""
    conn = get_db_connection()
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'User',
                ed25519_pubkey_hex TEXT,
                mlkem_ek_hex TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                kem_ciphertext_hex TEXT NOT NULL,
                nonce_hex TEXT NOT NULL,
                ciphertext_hex TEXT NOT NULL,
                tag_hex TEXT NOT NULL,
                signature_hex TEXT NOT NULL,
                is_tampered BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
    conn.close()


def create_user(username: str, password_hash: str, role: str = "User", ed25519_hex: str = "", mlkem_hex: str = "") -> bool:
    try:
        conn = get_db_connection()
        with conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, ed25519_pubkey_hex, mlkem_ek_hex) VALUES (?, ?, ?, ?, ?)",
                (username, password_hash, role, ed25519_hex, mlkem_hex)
            )
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False


def get_user(username: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_users() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, ed25519_pubkey_hex, mlkem_ek_hex, created_at FROM users")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_user_keys(username: str, ed25519_hex: str, mlkem_hex: str):
    conn = get_db_connection()
    with conn:
        conn.execute(
            "UPDATE users SET ed25519_pubkey_hex = ?, mlkem_ek_hex = ? WHERE username = ?",
            (ed25519_hex, mlkem_hex, username)
        )
    conn.close()


def save_message(
    sender: str,
    receiver: str,
    kem_ciphertext_hex: str,
    nonce_hex: str,
    ciphertext_hex: str,
    tag_hex: str,
    signature_hex: str,
    is_tampered: bool = False
) -> int:
    conn = get_db_connection()
    with conn:
        cur = conn.execute(
            """INSERT INTO messages 
               (sender, receiver, kem_ciphertext_hex, nonce_hex, ciphertext_hex, tag_hex, signature_hex, is_tampered) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (sender, receiver, kem_ciphertext_hex, nonce_hex, ciphertext_hex, tag_hex, signature_hex, is_tampered)
        )
        msg_id = cur.lastrowid
    conn.close()
    return msg_id


def get_messages(user1: str, user2: str) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT * FROM messages 
           WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?) 
           ORDER BY created_at ASC""",
        (user1, user2, user2, user1)
    )
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def log_audit(event_type: str, severity: str, details: str):
    conn = get_db_connection()
    with conn:
        conn.execute(
            "INSERT INTO audit_logs (event_type, severity, details) VALUES (?, ?, ?)",
            (event_type, severity, details)
        )
    conn.close()


def get_recent_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]
