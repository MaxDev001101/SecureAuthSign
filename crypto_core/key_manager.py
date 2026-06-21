from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

class KeyPair:
    """Custom data structure for cryptographic key pairs"""
    def __init__(self, user_id: str, algorithm: str = "RSA-2048"):
        self.user_id = user_id
        self.algorithm = algorithm
        if algorithm == "RSA-2048":
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif algorithm == "ECC-P256":
            self.private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        self.public_key = self.private_key.public_key()

    def get_private_pem(self, password: bytes = None) -> bytes:
        encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

    def get_public_pem(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def load_private(filepath: str, password: bytes = None):
        with open(filepath, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=password)

    @staticmethod
    def load_public(filepath: str):
        with open(filepath, "rb") as f:
            return serialization.load_pem_public_key(f.read())
