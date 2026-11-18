"""
QuantumShield Messenger - HKDF-SHA256 Key Derivation (RFC 5869)
Expands a 32-byte ML-KEM shared secret into a 256-bit symmetric session key.
"""
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class HKDFManager:
    DEFAULT_INFO = b"QuantumShield-AES-GCM-v1"
    DEFAULT_SALT = b"QuantumShield-Lattice-Salt-2026"

    @classmethod
    def derive_key(
        cls,
        shared_secret: bytes,
        salt: bytes = None,
        info: bytes = None,
        key_length: int = 32
    ) -> bytes:
        """Derives a 256-bit (32-byte) symmetric encryption key."""
        if salt is None:
            salt = cls.DEFAULT_SALT
        if info is None:
            info = cls.DEFAULT_INFO

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            info=info
        )
        return hkdf.derive(shared_secret)
