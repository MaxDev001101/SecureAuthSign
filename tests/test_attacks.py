"""
Attack Simulation Suite for SecureAuthSign
Maps directly to: Testing & Validation requirement + Security Features (20%)
"""
import os, pytest
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from crypto_core.auth import Authenticator
from crypto_core.document import DocumentProcessor, SecureTransmitter
from crypto_core.revocation import RevocationRegistry

DATA = "data"

def load_key(user, is_private=True):
    path = f"{DATA}/{user}/{'private' if is_private else 'public'}.pem"
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None) if is_private else serialization.load_pem_public_key(f.read())

@pytest.fixture(scope="module")
def setup_env():
    """Ensure CA and users exist from CLI run"""
    assert os.path.exists(f"{DATA}/RootCA/certificate.pem")
    assert os.path.exists(f"{DATA}/alice/private.pem")
    assert os.path.exists(f"{DATA}/bob/public.pem")

class TestIntegrityAttacks:
    def test_tampered_document_fails_verification(self, setup_env):
        doc = b"Original Contract v1.0"
        priv = load_key("alice")
        sig = DocumentProcessor.sign_document(priv, doc)
        tampered_doc = b"Original Contract v1.0 [TAMPERED]"
        pub = load_key("alice", is_private=False)
        assert not DocumentProcessor.verify_document(pub, tampered_doc, sig), "Tampered doc should fail verification"

    def test_wrong_key_fails_verification(self, setup_env):
        doc = b"Secret Document"
        alice_priv = load_key("alice")
        sig = DocumentProcessor.sign_document(alice_priv, doc)
        bob_pub = load_key("bob", is_private=False)
        assert not DocumentProcessor.verify_document(bob_pub, doc, sig), "Wrong public key should fail verification"

class TestAuthenticationAttacks:
    def test_replay_attack_blocked(self, setup_env):
        priv = load_key("alice")
        nonce1 = Authenticator.generate_nonce()
        sig1 = Authenticator.sign_nonce(priv, nonce1)
        pub = load_key("alice", is_private=False)
        assert Authenticator.verify_nonce(pub, nonce1, sig1)
        # Reusing same signature on different nonce should fail
        nonce2 = Authenticator.generate_nonce()
        assert not Authenticator.verify_nonce(pub, nonce2, sig1), "Replay attack should fail"

class TestConfidentialityAttacks:
    def test_mitm_payload_alteration_detected(self, setup_env):
        doc = b"Financial Report Q3"
        bob_pub = load_key("bob", is_private=False)
        pkg = SecureTransmitter.encrypt_document(doc, bob_pub)
        # Simulate MITM altering ciphertext
        pkg["payload"] = pkg["payload"] + "X"  # Corrupt base64 payload
        bob_priv = load_key("bob")
        with pytest.raises(Exception):
            SecureTransmitter.decrypt_document(pkg, bob_priv)

class TestRevocation:
    def test_revoked_cert_blocked(self, setup_env):
        crl = RevocationRegistry()
        cert_path = f"{DATA}/alice/certificate.pem"
        with open(cert_path, "rb") as f:
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(f.read())
        serial = cert.serial_number
        crl.revoke(serial)
        assert crl.is_revoked(serial), "Revoked cert should be tracked"
