
"""
QuantumShield Messenger
FastAPI Cryptographic Core Routes

Algorithms:
- ML-KEM-768 (NIST FIPS 203)
- HKDF-SHA256
- AES-256-GCM
- Ed25519
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..crypto.ml_kem import MLKEM768Manager
from ..crypto.kdf import HKDFManager
from ..crypto.aes_gcm import (
    AES256GCMCipher,
    TamperDetectedException
)
from ..crypto.signatures import Ed25519Manager
from ..database import get_user, log_audit
from ..auth import ACTIVE_PRIVATE_KEYS


router = APIRouter(
    prefix="/api/crypto",
    tags=["Cryptographic Pipeline"]
)


# -----------------------------
# REQUEST MODELS
# -----------------------------

class EncapsulateRequest(BaseModel):
    receiver_username: str


class DecapsulateRequest(BaseModel):
    receiver_username: str
    ciphertext_hex: str


class EncryptPayloadRequest(BaseModel):
    sender: str
    receiver: str
    plaintext: str
    simulate_tamper: bool = False


class DecryptPayloadRequest(BaseModel):
    receiver: str
    sender: str
    kem_ciphertext_hex: str
    nonce_hex: str
    ciphertext_hex: str
    tag_hex: str
    signature_hex: str


# -----------------------------
# HEX VALIDATION
# -----------------------------

def decode_hex(value: str, field_name: str) -> bytes:
    """Safely decode hexadecimal input."""

    try:
        return bytes.fromhex(value)

    except (ValueError, TypeError):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid hexadecimal input: {field_name}"
        )


# -----------------------------
# 1. KEY GENERATION
# -----------------------------

@router.post("/keygen")
def generate_keypair():
    """Generate an ML-KEM-768 keypair."""

    kp = MLKEM768Manager.generate_keypair()

    return {
        "status": "success",
        "algorithm": "ML-KEM-768 (NIST FIPS 203)",
        "public_key_hex": kp.public_key_hex,
        "public_key_bytes_len": len(kp.public_key),
        "private_key_bytes_len": len(kp.private_key)
    }


# -----------------------------
# 2. KEY ENCAPSULATION
# -----------------------------

@router.post("/encapsulate")
def encapsulate(req: EncapsulateRequest):
    """Encapsulate a shared secret using receiver's public key."""

    user = get_user(req.receiver_username)

    if not user or not user["mlkem_ek_hex"]:
        raise HTTPException(
            status_code=404,
            detail="Receiver ML-KEM public key not found."
        )

    pub_bytes = decode_hex(
        user["mlkem_ek_hex"],
        "receiver public key"
    )

    try:
        shared_secret, kem_ciphertext = (
            MLKEM768Manager.encapsulate(pub_bytes)
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Never expose shared_secret or session_key in API responses.

    log_audit(
        "KEM_ENCAPS",
        "INFO",
        f"ML-KEM encapsulation completed for '{req.receiver_username}'."
    )

    return {
        "status": "success",
        "algorithm": "ML-KEM-768",
        "kem_ciphertext_hex": kem_ciphertext.hex(),
        "message": "KEM encapsulation completed successfully."
    }


# -----------------------------
# 3. MESSAGE ENCRYPTION
# -----------------------------

@router.post("/encrypt")
def encrypt_message(req: EncryptPayloadRequest):
    """
    Encryption pipeline:

    ML-KEM-768
        -> HKDF-SHA256
        -> AES-256-GCM
        -> Ed25519 Signature
    """

    receiver = get_user(req.receiver)

    sender_keys = ACTIVE_PRIVATE_KEYS.get(req.sender)

    if not receiver or not receiver["mlkem_ek_hex"]:
        raise HTTPException(
            status_code=404,
            detail="Receiver public key missing."
        )

    if not sender_keys:
        raise HTTPException(
            status_code=400,
            detail="Sender private key not found in enclave."
        )

    # 1. ML-KEM-768 encapsulation

    ek = decode_hex(
        receiver["mlkem_ek_hex"],
        "receiver public key"
    )

    try:
        shared_secret, kem_ct = (
            MLKEM768Manager.encapsulate(ek)
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 2. HKDF-SHA256 key derivation

    session_key = HKDFManager.derive_key(shared_secret)

    # 3. AES-256-GCM encryption

    cipher = AES256GCMCipher(session_key)

    payload = cipher.encrypt(req.plaintext)

    ciphertext_bytes = bytearray(payload.ciphertext)

    is_tampered = req.simulate_tamper

    # Simulate ciphertext tampering for security testing.

    if is_tampered and len(ciphertext_bytes) > 0:
        ciphertext_bytes[0] ^= 0x01

    final_ciphertext = bytes(ciphertext_bytes)

    # 4. Ed25519 digital signature

    to_sign = (
        kem_ct
        + payload.nonce
        + final_ciphertext
        + payload.tag
    )

    sig = Ed25519Manager.sign(
        sender_keys["ed25519_priv"],
        to_sign
    )

    log_audit(
        "PAYLOAD_ENCRYPTED",
        "WARNING" if is_tampered else "INFO",
        f"Encrypted message for {req.receiver}. "
        f"Tamper simulation: {is_tampered}."
    )

    # Return encrypted packet only.
    # Never return shared_secret or session_key.

    return {
        "status": "success",
        "sender": req.sender,
        "receiver": req.receiver,
        "kem_ciphertext_hex": kem_ct.hex(),
        "nonce_hex": payload.nonce.hex(),
        "ciphertext_hex": final_ciphertext.hex(),
        "tag_hex": payload.tag.hex(),
        "signature_hex": sig.hex(),
        "is_tampered": is_tampered
    }


# -----------------------------
# 4. MESSAGE DECRYPTION
# -----------------------------

@router.post("/decrypt")
def decrypt_message(req: DecryptPayloadRequest):
    """
    Decryption pipeline:

    Ed25519 Verification
        -> ML-KEM-768 Decapsulation
        -> HKDF-SHA256
        -> AES-256-GCM Decryption
    """

    receiver_keys = ACTIVE_PRIVATE_KEYS.get(req.receiver)

    sender = get_user(req.sender)

    if not receiver_keys or "mlkem_dk" not in receiver_keys:
        raise HTTPException(
            status_code=400,
            detail="Receiver private decapsulation key missing."
        )

    if not sender or not sender["ed25519_pubkey_hex"]:
        raise HTTPException(
            status_code=404,
            detail="Sender Ed25519 identity key not found."
        )

    # Decode incoming encrypted packet.

    kem_ct = decode_hex(
        req.kem_ciphertext_hex,
        "KEM ciphertext"
    )

    nonce = decode_hex(
        req.nonce_hex,
        "nonce"
    )

    ciphertext = decode_hex(
        req.ciphertext_hex,
        "ciphertext"
    )

    tag = decode_hex(
        req.tag_hex,
        "authentication tag"
    )

    sig = decode_hex(
        req.signature_hex,
        "digital signature"
    )

    sender_pub = decode_hex(
        sender["ed25519_pubkey_hex"],
        "sender public key"
    )

    # 1. Ed25519 signature verification

    to_verify = kem_ct + nonce + ciphertext + tag

    try:
        valid_sig = Ed25519Manager.verify(
            sender_pub,
            sig,
            to_verify
        )

    except (ValueError, TypeError):
        valid_sig = False

    if not valid_sig:

        log_audit(
            "SIG_VERIFY_FAILED",
            "CRITICAL",
            f"Invalid Ed25519 signature from '{req.sender}'."
        )

        raise HTTPException(
            status_code=400,
            detail="Identity Verification Failed: Ed25519 signature invalid."
        )

    # 2. ML-KEM-768 decapsulation

    try:
        shared_secret = MLKEM768Manager.decapsulate(
            receiver_keys["mlkem_dk"],
            kem_ct
        )

    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=f"ML-KEM decapsulation failed: {e}"
        )

    # 3. HKDF-SHA256 session key derivation

    session_key = HKDFManager.derive_key(shared_secret)

    # 4. AES-256-GCM authenticated decryption

    cipher = AES256GCMCipher(session_key)

    try:

        plaintext_bytes = cipher.decrypt(
            nonce,
            ciphertext,
            tag
        )

        plaintext = plaintext_bytes.decode("utf-8")

        log_audit(
            "PAYLOAD_DECRYPTED",
            "INFO",
            f"Decrypted payload from '{req.sender}'. "
            "AES-GCM authentication successful."
        )

        return {
            "status": "success",
            "plaintext": plaintext,
            "gmac_verified": True,
            "ed25519_verified": True
        }

    except TamperDetectedException as e:

        log_audit(
            "TAMPER_DETECTED",
            "CRITICAL",
            f"AES-GCM authentication failed for packet from '{req.sender}'."
        )

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

    except UnicodeDecodeError:

        raise HTTPException(
            status_code=400,
            detail="Decrypted message is not valid UTF-8."
        )
