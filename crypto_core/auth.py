import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class Authenticator:
    @staticmethod
    def generate_nonce(size=32) -> bytes:
        return os.urandom(size)

    @staticmethod
    def sign_nonce(private_key, nonce: bytes) -> bytes:
        return private_key.sign(nonce, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    @staticmethod
    def verify_nonce(public_key, nonce: bytes, signature: bytes) -> bool:
        try:
            public_key.verify(signature, nonce, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except Exception:
            return False
