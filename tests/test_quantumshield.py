"""
QuantumShield Messenger - Comprehensive Cryptographic & System Test Suite.
Verifies ML-KEM-768, HKDF-SHA256, AES-256-GCM, Ed25519, and GMAC Tamper Detection.
"""
import pytest
from backend.crypto.ml_kem import MLKEM768Manager
from backend.crypto.kdf import HKDFManager
from backend.crypto.aes_gcm import AES256GCMCipher, TamperDetectedException
from backend.crypto.signatures import Ed25519Manager
from backend.database import init_db, get_user, save_message, get_messages
from backend.auth import hash_password, verify_password, seed_default_users


def test_ml_kem_768_key_encapsulation():
    """Verify ML-KEM-768 key generation, encapsulation, and decapsulation."""
    # Receiver generates keypair
    keypair = MLKEM768Manager.generate_keypair()
    assert len(keypair.public_key) == MLKEM768Manager.PUBLIC_KEY_SIZE
    assert len(keypair.private_key) == MLKEM768Manager.PRIVATE_KEY_SIZE

    # Sender encapsulates shared secret
    sender_ss, ciphertext = MLKEM768Manager.encapsulate(keypair.public_key)
    assert len(sender_ss) == MLKEM768Manager.SHARED_SECRET_SIZE
    assert len(ciphertext) == MLKEM768Manager.CIPHERTEXT_SIZE

    # Receiver decapsulates shared secret
    receiver_ss = MLKEM768Manager.decapsulate(keypair.private_key, ciphertext)
    assert len(receiver_ss) == MLKEM768Manager.SHARED_SECRET_SIZE

    # Both shared secrets MUST be bit-identical
    assert sender_ss == receiver_ss


def test_hkdf_sha256_derivation():
    """Verify HKDF-SHA256 derives consistent 256-bit symmetric keys."""
    shared_secret = b"\x42" * 32
    key1 = HKDFManager.derive_key(shared_secret)
    key2 = HKDFManager.derive_key(shared_secret)

    assert len(key1) == 32
    assert key1 == key2


def test_aes_256_gcm_encryption_and_decryption():
    """Verify authenticated AES-256-GCM encryption and decryption."""
    session_key = b"\x01" * 32
    cipher = AES256GCMCipher(session_key)

    plaintext = "CONFIDENTIAL: QuantumShield Post-Quantum Key Exchange Protocol"
    payload = cipher.encrypt(plaintext)

    assert len(payload.nonce) == 12
    assert len(payload.tag) == 16
    assert payload.ciphertext != plaintext.encode("utf-8")

    decrypted = cipher.decrypt(payload.nonce, payload.ciphertext, payload.tag)
    assert decrypted.decode("utf-8") == plaintext


def test_gmac_tamper_detection():
    """Verify modifying 1 bit of ciphertext raises TamperDetectedException."""
    session_key = b"\x02" * 32
    cipher = AES256GCMCipher(session_key)

    plaintext = "Top Secret Information"
    payload = cipher.encrypt(plaintext)

    # Simulate MITM adversary flipping 1 bit
    tampered_ciphertext = bytearray(payload.ciphertext)
    tampered_ciphertext[0] ^= 0x01

    with pytest.raises(TamperDetectedException):
        cipher.decrypt(payload.nonce, bytes(tampered_ciphertext), payload.tag)


def test_ed25519_digital_signature():
    """Verify Ed25519 signing and verification for non-repudiation."""
    keypair = Ed25519Manager.generate_keypair()
    message = b"Authenticated Quantum Payload from Nova"

    signature = Ed25519Manager.sign(keypair.private_key, message)
    assert len(signature) == 64

    # Verification must succeed
    assert Ed25519Manager.verify(keypair.public_bytes, signature, message) is True

    # Verification must fail with modified message
    assert Ed25519Manager.verify(keypair.public_bytes, signature, b"Tampered Message") is False


def test_database_and_auth():
    """Verify database initialization, password hashing, and user seeding."""
    init_db()
    seed_default_users()

    user_nova = get_user("Nova")
    assert user_nova is not None
    assert user_nova["username"] == "Nova"
    assert user_nova["mlkem_ek_hex"] is not None

    assert verify_password(user_nova["password_hash"], "nova123") is True
    assert verify_password(user_nova["password_hash"], "wrongpassword") is False
