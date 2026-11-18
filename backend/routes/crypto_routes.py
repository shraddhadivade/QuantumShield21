"""
FastAPI Cryptographic Core Routes (ML-KEM-768, HKDF-SHA256, AES-256-GCM, Ed25519).
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from ..crypto.ml_kem import MLKEM768Manager
from ..crypto.kdf import HKDFManager
from ..crypto.aes_gcm import AES256GCMCipher, TamperDetectedException
from ..crypto.signatures import Ed25519Manager
from ..database import get_user, update_user_keys, log_audit
from ..auth import ACTIVE_PRIVATE_KEYS

router = APIRouter(prefix="/api/crypto", tags=["Cryptographic Pipeline"])


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


@router.post("/keygen")
def generate_keypair():
    """Generates an ML-KEM-768 keypair on demand."""
    kp = MLKEM768Manager.generate_keypair()
    return {
        "status": "success",
        "algorithm": "ML-KEM-768 (NIST FIPS 203)",
        "public_key_hex": kp.public_key_hex,
        "public_key_bytes_len": len(kp.public_key),
        "private_key_bytes_len": len(kp.private_key)
    }


@router.post("/encapsulate")
def encapsulate(req: EncapsulateRequest):
    """Encapsulates a shared secret using recipient's ML-KEM-768 public key."""
    user = get_user(req.receiver_username)
    if not user or not user["mlkem_ek_hex"]:
        raise HTTPException(status_code=404, detail="Receiver ML-KEM public key not found.")

    pub_bytes = bytes.fromhex(user["mlkem_ek_hex"])
    shared_secret, kem_ciphertext = MLKEM768Manager.encapsulate(pub_bytes)
    session_key = HKDFManager.derive_key(shared_secret)

    log_audit("KEM_ENCAPS", "INFO", f"Encapsulated 32-byte shared secret against '{req.receiver_username}' ek.")
    return {
        "status": "success",
        "kem_ciphertext_hex": kem_ciphertext.hex(),
        "shared_secret_hex": shared_secret.hex(),
        "derived_session_key_hex": session_key.hex()
    }


@router.post("/encrypt")
def encrypt_message(req: EncryptPayloadRequest):
    """Full end-to-end pipeline: ML-KEM -> HKDF -> AES-256-GCM -> Ed25519 Sign."""
    receiver = get_user(req.receiver)
    sender_keys = ACTIVE_PRIVATE_KEYS.get(req.sender)

    if not receiver or not receiver["mlkem_ek_hex"]:
        raise HTTPException(status_code=404, detail="Receiver public key missing.")
    if not sender_keys:
        raise HTTPException(status_code=400, detail="Sender private key not found in enclave.")

    # 1. Post-Quantum KEM
    ek = bytes.fromhex(receiver["mlkem_ek_hex"])
    shared_secret, kem_ct = MLKEM768Manager.encapsulate(ek)

    # 2. Key Derivation via HKDF-SHA256
    session_key = HKDFManager.derive_key(shared_secret)

    # 3. Authenticated Payload Encryption via AES-256-GCM
    cipher = AES256GCMCipher(session_key)
    payload = cipher.encrypt(req.plaintext)

    ciphertext_bytes = bytearray(payload.ciphertext)
    is_tampered = req.simulate_tamper

    # If tamper requested (MITM attack simulation), flip 1 bit
    if is_tampered and len(ciphertext_bytes) > 0:
        ciphertext_bytes[0] ^= 0x01  # Flip single bit

    final_ciphertext_hex = bytes(ciphertext_bytes).hex()

    # 4. Digital Signature with Ed25519 for Non-Repudiation
    to_sign = kem_ct + payload.nonce + bytes(ciphertext_bytes) + payload.tag
    sig = Ed25519Manager.sign(sender_keys["ed25519_priv"], to_sign)

    log_audit(
        "PAYLOAD_ENCRYPTED",
        "INFO" if not is_tampered else "WARNING",
        f"Encrypted message for {req.receiver} via AES-256-GCM. Tamper flag: {is_tampered}."
    )

    return {
        "status": "success",
        "sender": req.sender,
        "receiver": req.receiver,
        "kem_ciphertext_hex": kem_ct.hex(),
        "nonce_hex": payload.nonce.hex(),
        "ciphertext_hex": final_ciphertext_hex,
        "tag_hex": payload.tag.hex(),
        "signature_hex": sig.hex(),
        "is_tampered": is_tampered
    }


@router.post("/decrypt")
def decrypt_message(req: DecryptPayloadRequest):
    """Full decryption pipeline: Verify Ed25519 -> ML-KEM Decaps -> HKDF -> AES-256-GCM Decrypt."""
    receiver_keys = ACTIVE_PRIVATE_KEYS.get(req.receiver)
    sender = get_user(req.sender)

    if not receiver_keys or "mlkem_dk" not in receiver_keys:
        raise HTTPException(status_code=400, detail="Receiver private decapsulation key missing.")
    if not sender or not sender["ed25519_pubkey_hex"]:
        raise HTTPException(status_code=404, detail="Sender Ed25519 identity key not found.")

    kem_ct = bytes.fromhex(req.kem_ciphertext_hex)
    nonce = bytes.fromhex(req.nonce_hex)
    ciphertext = bytes.fromhex(req.ciphertext_hex)
    tag = bytes.fromhex(req.tag_hex)
    sig = bytes.fromhex(req.signature_hex)
    sender_pub = bytes.fromhex(sender["ed25519_pubkey_hex"])

    # 1. Verify Ed25519 Signature
    to_verify = kem_ct + nonce + ciphertext + tag
    valid_sig = Ed25519Manager.verify(sender_pub, sig, to_verify)
    if not valid_sig:
        log_audit("SIG_VERIFY_FAILED", "CRITICAL", f"Invalid Ed25519 signature from '{req.sender}'!")
        raise HTTPException(status_code=400, detail="Identity Verification Failed: Ed25519 signature invalid.")

    # 2. Decapsulate ML-KEM Shared Secret
    shared_secret = MLKEM768Manager.decapsulate(receiver_keys["mlkem_dk"], kem_ct)

    # 3. Derive Symmetric Key
    session_key = HKDFManager.derive_key(shared_secret)

    # 4. Decrypt via AES-256-GCM & Check GMAC Tag
    cipher = AES256GCMCipher(session_key)
    try:
        plaintext_bytes = cipher.decrypt(nonce, ciphertext, tag)
        plaintext = plaintext_bytes.decode("utf-8")
        log_audit("PAYLOAD_DECRYPTED", "INFO", f"Decrypted payload from {req.sender}. GMAC Tag Verified.")
        return {
            "status": "success",
            "plaintext": plaintext,
            "gmac_verified": True,
            "ed25519_verified": True
        }
    except TamperDetectedException as e:
        log_audit("TAMPER_DETECTED", "CRITICAL", f"GMAC Tag validation failed for packet from '{req.sender}'!")
        raise HTTPException(status_code=400, detail=str(e))
