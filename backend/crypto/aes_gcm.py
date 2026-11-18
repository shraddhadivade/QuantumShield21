"""
QuantumShield Messenger - AES-256-GCM Implementation (NIST SP 800-38D)
Provides authenticated encryption and GMAC tamper-proof verification.
"""
from dataclasses import dataclass
from typing import Optional, Tuple
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class TamperDetectedException(Exception):
    """Raised when ciphertext, nonce, or GMAC authentication tag has been tampered with."""
    pass


@dataclass
class EncryptedPayload:
    nonce: bytes        # 12-byte initialization vector (96-bit)
    ciphertext: bytes   # Encrypted message payload
    tag: bytes          # 16-byte GMAC authentication tag (128-bit)

    @property
    def combined(self) -> bytes:
        return self.ciphertext + self.tag


class AES256GCMCipher:
    NONCE_SIZE = 12   # 96 bits recommended by NIST
    TAG_SIZE = 16     # 128 bits GMAC tag
    KEY_SIZE = 32     # 256 bits

    def __init__(self, key: bytes):
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)} bytes.")
        self.key = bytes(key)
        self._aesgcm = AESGCM(self.key)

    def encrypt(
        self,
        plaintext: str | bytes,
        associated_data: Optional[bytes] = None,
        custom_nonce: Optional[bytes] = None
    ) -> EncryptedPayload:
        """Encrypts plaintext with AES-256-GCM and generates a 128-bit authentication tag."""
        data_bytes = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
        nonce = custom_nonce if custom_nonce is not None else os.urandom(self.NONCE_SIZE)

        raw = self._aesgcm.encrypt(nonce, data_bytes, associated_data)
        ciphertext = raw[:-self.TAG_SIZE]
        tag = raw[-self.TAG_SIZE:]

        return EncryptedPayload(nonce=nonce, ciphertext=ciphertext, tag=tag)

    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """Decrypts ciphertext and verifies GMAC tag. Raises TamperDetectedException on mismatch."""
        try:
            combined = ciphertext + tag
            return self._aesgcm.decrypt(nonce, combined, associated_data)
        except InvalidTag as e:
            raise TamperDetectedException(
                "[SECURITY ALERT] GMAC tag verification failed! Ciphertext or nonce modified in transit."
            ) from e
