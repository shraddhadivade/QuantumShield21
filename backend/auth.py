"""
QuantumShield Messenger - Authentication & Identity Management
Handles PBKDF2-HMAC-SHA256 password security, Ed25519 identity generation, and seed users.
"""
import hashlib
import os
import binascii
from typing import Optional, Tuple
from .database import create_user, get_user, update_user_keys, log_audit
from .crypto.signatures import Ed25519Manager
from .crypto.ml_kem import MLKEM768Manager

SALT_SIZE = 16
ITERATIONS = 100_000


def hash_password(password: str) -> str:
    salt = os.urandom(SALT_SIZE)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return binascii.hexlify(salt).decode("ascii") + "$" + binascii.hexlify(key).decode("ascii")


def verify_password(stored_password: str, provided_password: str) -> bool:
    try:
        salt_hex, key_hex = stored_password.split("$")
        salt = binascii.unhexlify(salt_hex)
        expected_key = binascii.unhexlify(key_hex)
        key = hashlib.pbkdf2_hmac("sha256", provided_password.encode("utf-8"), salt, ITERATIONS)
        return hashlib.sha256(key).digest() == hashlib.sha256(expected_key).digest()
    except Exception:
        return False


# In-memory store for active session keypairs (ephemeral private keys)
ACTIVE_PRIVATE_KEYS = {
    # username -> {"ed25519_priv": key, "mlkem_dk": bytes}
}


def seed_default_users():
    """Seeds default quantum nodes (Nova, Orion, Alice, Eve) with initial cryptographic parameters."""
    defaults = [
        ("Nova", "nova123", "Security Engineer (Sender)"),
        ("Orion", "orion123", "Quantum Node (Receiver)"),
        ("Alice", "alice123", "Cryptographic Auditor"),
        ("Eve", "eve123", "Adversary (MITM Probe)"),
    ]

    for username, password, role in defaults:
        if not get_user(username):
            # Generate cryptographic keys
            ed_pair = Ed25519Manager.generate_keypair()
            kem_pair = MLKEM768Manager.generate_keypair()

            pwd_hash = hash_password(password)
            create_user(
                username=username,
                password_hash=pwd_hash,
                role=role,
                ed25519_hex=ed_pair.public_hex,
                mlkem_hex=kem_pair.public_key_hex
            )

            # Cache private keys in memory
            ACTIVE_PRIVATE_KEYS[username] = {
                "ed25519_priv": ed_pair.private_key,
                "mlkem_dk": kem_pair.private_key
            }

            log_audit(
                event_type="NODE_REGISTERED",
                severity="INFO",
                details=f"Node '{username}' initialized with ML-KEM-768 ({len(kem_pair.public_key)} bytes ek) and Ed25519."
            )
