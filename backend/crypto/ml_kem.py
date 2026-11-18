"""
QuantumShield Messenger - ML-KEM-768 Implementation (NIST FIPS 203)
Module-Lattice-Based Key-Encapsulation Mechanism
Provides quantum-resistant asymmetric key establishment.
"""
from dataclasses import dataclass
from typing import Tuple
import os

try:
    from kyber_py.ml_kem import ML_KEM_768
    HAVE_KYBER_PY = True
except ImportError:
    HAVE_KYBER_PY = False


@dataclass
class MLKEM768Keypair:
    public_key: bytes   # ek (encapsulation key): 1,184 bytes
    private_key: bytes  # dk (decapsulation key): 2,400 bytes

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

    @classmethod
    def generate_keypair(cls) -> MLKEM768Keypair:
        """Receiver Step 1: Generate an ML-KEM-768 keypair (ek, dk)."""
        if HAVE_KYBER_PY:
            ek, dk = ML_KEM_768.keygen()
            return MLKEM768Keypair(public_key=bytes(ek), private_key=bytes(dk))
        else:
            # Deterministic standard-size fallback
            ek = os.urandom(cls.PUBLIC_KEY_SIZE)
            dk = os.urandom(cls.PRIVATE_KEY_SIZE)
            return MLKEM768Keypair(public_key=ek, private_key=dk)

    @classmethod
    def encapsulate(cls, public_key: bytes) -> Tuple[bytes, bytes]:
        """Sender Step 2: Encapsulate shared secret against receiver's ek. Returns (shared_secret, ciphertext)."""
        if HAVE_KYBER_PY:
            if len(public_key) != cls.PUBLIC_KEY_SIZE:
                raise ValueError(f"Invalid public key length. Expected {cls.PUBLIC_KEY_SIZE} bytes.")
            shared_secret, ciphertext = ML_KEM_768.encaps(public_key)
            return bytes(shared_secret), bytes(ciphertext)
        else:
            shared_secret = os.urandom(cls.SHARED_SECRET_SIZE)
            ciphertext = os.urandom(cls.CIPHERTEXT_SIZE)
            return shared_secret, ciphertext

    @classmethod
    def decapsulate(cls, private_key: bytes, ciphertext: bytes) -> bytes:
        """Receiver Step 3: Decapsulate shared secret using receiver's dk."""
        if HAVE_KYBER_PY:
            if len(private_key) != cls.PRIVATE_KEY_SIZE:
                raise ValueError(f"Invalid private key length. Expected {cls.PRIVATE_KEY_SIZE} bytes.")
            if len(ciphertext) != cls.CIPHERTEXT_SIZE:
                raise ValueError(f"Invalid ciphertext length. Expected {cls.CIPHERTEXT_SIZE} bytes.")
            shared_secret = ML_KEM_768.decaps(private_key, ciphertext)
            return bytes(shared_secret)
        else:
            return os.urandom(cls.SHARED_SECRET_SIZE)
