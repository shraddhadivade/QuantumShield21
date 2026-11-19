
"""
QuantumShield Messenger - ML-KEM-768 Implementation
Standard: NIST FIPS 203
Library: kyber-py

Provides genuine post-quantum key establishment.
No insecure fallback implementation is permitted.
"""

from dataclasses import dataclass
from typing import Tuple

try:
    from kyber_py.ml_kem import ML_KEM_768
    HAVE_KYBER_PY = True

except ImportError:
    ML_KEM_768 = None
    HAVE_KYBER_PY = False


@dataclass
class MLKEM768Keypair:
    public_key: bytes
    private_key: bytes

    @property
    def public_key_hex(self) -> str:
        return self.public_key.hex()

    @property
    def private_key_hex(self) -> str:
        return self.private_key.hex()


class MLKEM768Manager:

    PUBLIC_KEY_SIZE = 1184
    PRIVATE_KEY_SIZE = 2400
    CIPHERTEXT_SIZE = 1088
    SHARED_SECRET_SIZE = 32

    @staticmethod
    def _require_library():
        if not HAVE_KYBER_PY:
            raise RuntimeError(
                "ML-KEM-768 unavailable. "
                "Install the required package using: "
                "py -m pip install kyber-py"
            )

    @classmethod
    def generate_keypair(cls) -> MLKEM768Keypair:
        """Generate a genuine ML-KEM-768 keypair."""

        cls._require_library()

        ek, dk = ML_KEM_768.keygen()

        public_key = bytes(ek)
        private_key = bytes(dk)

        if len(public_key) != cls.PUBLIC_KEY_SIZE:
            raise ValueError("Invalid ML-KEM-768 public key size.")

        if len(private_key) != cls.PRIVATE_KEY_SIZE:
            raise ValueError("Invalid ML-KEM-768 private key size.")

        return MLKEM768Keypair(
            public_key=public_key,
            private_key=private_key
        )

    @classmethod
    def encapsulate(cls, public_key: bytes) -> Tuple[bytes, bytes]:
        """Generate shared secret and ciphertext using receiver's public key."""

        cls._require_library()

        if len(public_key) != cls.PUBLIC_KEY_SIZE:
            raise ValueError(
                f"Invalid public key length. "
                f"Expected {cls.PUBLIC_KEY_SIZE} bytes."
            )

        shared_secret, ciphertext = ML_KEM_768.encaps(public_key)

        shared_secret = bytes(shared_secret)
        ciphertext = bytes(ciphertext)

        if len(shared_secret) != cls.SHARED_SECRET_SIZE:
            raise ValueError("Invalid shared secret size.")

        if len(ciphertext) != cls.CIPHERTEXT_SIZE:
            raise ValueError("Invalid ciphertext size.")

        return shared_secret, ciphertext

    @classmethod
    def decapsulate(
        cls,
        private_key: bytes,
        ciphertext: bytes
    ) -> bytes:
        """Recover shared secret using receiver's private key."""

        cls._require_library()

        if len(private_key) != cls.PRIVATE_KEY_SIZE:
            raise ValueError(
                f"Invalid private key length. "
                f"Expected {cls.PRIVATE_KEY_SIZE} bytes."
            )

        if len(ciphertext) != cls.CIPHERTEXT_SIZE:
            raise ValueError(
                f"Invalid ciphertext length. "
                f"Expected {cls.CIPHERTEXT_SIZE} bytes."
            )

        shared_secret = ML_KEM_768.decaps(
            private_key,
            ciphertext
        )

        shared_secret = bytes(shared_secret)

        if len(shared_secret) != cls.SHARED_SECRET_SIZE:
            raise ValueError("Invalid shared secret size.")

        return shared_secret
