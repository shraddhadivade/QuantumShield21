"""
QuantumShield Messenger - Ed25519 Digital Signatures (RFC 8032)
Provides sender authentication, identity verification, and non-repudiation.
"""
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


@dataclass
class Ed25519Keypair:
    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey

    @property
    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes_raw()

    @property
    def public_hex(self) -> str:
        return self.public_bytes.hex()


class Ed25519Manager:
    @classmethod
    def generate_keypair(cls) -> Ed25519Keypair:
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        return Ed25519Keypair(private_key=priv, public_key=pub)

    @classmethod
    def sign(cls, private_key: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
        """Signs data with sender's Ed25519 private key (64-byte signature)."""
        return private_key.sign(data)

    @classmethod
    def verify(cls, public_key_bytes: bytes, signature: bytes, data: bytes) -> bool:
        """Verifies Ed25519 signature against sender's public key."""
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub.verify(signature, data)
            return True
        except InvalidSignature:
            return False
