"""
QuantumShield Messenger - API Test Suite
Tests authentication, cryptography, messaging and attack simulation.
"""

import pytest
from fastapi.testclient import TestClient

import backend.database as database
from backend.app import app
from backend.auth import ACTIVE_PRIVATE_KEYS


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Use an isolated temporary database for every API test."""

    test_db = tmp_path / "test_quantumshield.db"
    monkeypatch.setattr(database, "DB_FILE", str(test_db))

    ACTIVE_PRIVATE_KEYS.clear()

    with TestClient(app) as test_client:
        yield test_client

    ACTIVE_PRIVATE_KEYS.clear()


# 1. Authentication Tests

def test_login_success(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "Nova", "password": "nova123"}
    )

    assert response.status_code == 200
    assert response.json()["status"] == "success"


def test_login_invalid_password(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "Nova", "password": "wrong123"}
    )

    assert response.status_code == 401


def test_user_registration(client):
    response = client.post(
        "/api/auth/register",
        json={
            "username": "TestUser",
            "password": "test123",
            "role": "Tester"
        }
    )

    assert response.status_code == 200
    assert response.json()["username"] == "TestUser"


# 2. Cryptographic API Tests

def test_key_generation(client):
    response = client.post("/api/crypto/keygen")

    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert response.json()["algorithm"].startswith("ML-KEM-768")


def test_key_encapsulation(client):
    response = client.post(
        "/api/crypto/encapsulate",
        json={"receiver_username": "Orion"}
    )

    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert "kem_ciphertext_hex" in response.json()


# 3. End-to-End Encryption and Decryption

def test_encryption_decryption(client):
    message = "Hello Orion! Secure QuantumShield message."

    encrypted = client.post(
        "/api/crypto/encrypt",
        json={
            "sender": "Nova",
            "receiver": "Orion",
            "plaintext": message
        }
    )

    assert encrypted.status_code == 200

    packet = encrypted.json()

    decrypted = client.post(
        "/api/crypto/decrypt",
        json={
            "receiver": "Orion",
            "sender": "Nova",
            "kem_ciphertext_hex": packet["kem_ciphertext_hex"],
            "nonce_hex": packet["nonce_hex"],
            "ciphertext_hex": packet["ciphertext_hex"],
            "tag_hex": packet["tag_hex"],
            "signature_hex": packet["signature_hex"]
        }
    )

    assert decrypted.status_code == 200
    assert decrypted.json()["plaintext"] == message
    assert decrypted.json()["gmac_verified"] is True
    assert decrypted.json()["ed25519_verified"] is True


# 4. Tamper Detection Test

def test_tampered_message_rejected(client):
    encrypted = client.post(
        "/api/crypto/encrypt",
        json={
            "sender": "Nova",
            "receiver": "Orion",
            "plaintext": "Confidential message",
            "simulate_tamper": True
        }
    )

    assert encrypted.status_code == 200

    packet = encrypted.json()

    decrypted = client.post(
        "/api/crypto/decrypt",
        json={
            "receiver": "Orion",
            "sender": "Nova",
            "kem_ciphertext_hex": packet["kem_ciphertext_hex"],
            "nonce_hex": packet["nonce_hex"],
            "ciphertext_hex": packet["ciphertext_hex"],
            "tag_hex": packet["tag_hex"],
            "signature_hex": packet["signature_hex"]
        }
    )

    assert decrypted.status_code == 400


# 5. Chat API Test

def test_send_and_get_message_history(client):
    packet = {
        "sender": "Nova",
        "receiver": "Orion",
        "kem_ciphertext_hex": "aabb",
        "nonce_hex": "ccdd",
        "ciphertext_hex": "eeff",
        "tag_hex": "1122",
        "signature_hex": "3344"
    }

    sent = client.post("/api/chat/send", json=packet)

    assert sent.status_code == 200
    assert sent.json()["status"] == "success"

    history = client.get("/api/chat/history/Nova/Orion")

    assert history.status_code == 200
    assert len(history.json()["messages"]) == 1


# 6. Attack Simulation Tests

def test_mitm_tamper_simulation(client):
    response = client.post(
        "/api/attack/mitm-tamper",
        json={"ciphertext_hex": "aabbcc"}
    )

    assert response.status_code == 200
    assert response.json()["status"] == "tampered"
    assert response.json()["tampered_hex"] == "abbbcc"


def test_replay_attack_simulation(client):
    response = client.post(
        "/api/attack/replay-test",
        json={
            "packet_id": 1,
            "captured_nonce_hex": "aabbcc"
        }
    )

    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    assert response.json()["is_replay"] is True


def test_hndl_metrics(client):
    response = client.get("/api/attack/hndl-metrics")

    assert response.status_code == 200
    assert "quantum_threat_index" in response.json()

