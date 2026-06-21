import os, json, base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class DocumentProcessor:
    @staticmethod
    def sign_document(private_key, doc_bytes: bytes) -> bytes:
        h = hashes.Hash(hashes.SHA256())
        h.update(doc_bytes)
        return private_key.sign(h.finalize(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    @staticmethod
    def verify_document(public_key, doc_bytes: bytes, signature: bytes) -> bool:
        h = hashes.Hash(hashes.SHA256())
        h.update(doc_bytes)
        try:
            public_key.verify(signature, h.finalize(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except Exception:
            return False

class SecureTransmitter:
    @staticmethod
    def encrypt_document(doc_bytes: bytes, recipient_public_key) -> dict:
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        ciphertext = AESGCM(aes_key).encrypt(nonce, doc_bytes, None)
        encrypted_key = recipient_public_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return {"nonce": base64.b64encode(nonce).decode(), "encrypted_key": base64.b64encode(encrypted_key).decode(), "payload": base64.b64encode(ciphertext).decode()}

    @staticmethod
    def decrypt_document(package: dict, recipient_private_key) -> bytes:
        aes_key = recipient_private_key.decrypt(base64.b64decode(package["encrypted_key"]), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return AESGCM(aes_key).decrypt(base64.b64decode(package["nonce"]), base64.b64decode(package["payload"]), None)
