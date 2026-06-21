from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
import datetime

class Certificate:
    """Custom wrapper for X.509 certificates"""
    def __init__(self, subject_name: str, public_key, issuer_private_key, 
                 issuer_name: str = "SecureAuthSign-RootCA", days_valid=365, is_ca=False):
        self.subject_name = subject_name
        self.issuer_name = issuer_name
        self.public_key = public_key  # Already a public key object
        self.days_valid = days_valid
        self.is_ca = is_ca
        self.certificate = self._generate(issuer_private_key)

    def _generate(self, issuer_private_key) -> x509.Certificate:
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.subject_name if self.is_ca else self.subject_name),
        ])
        if not self.is_ca:
            issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.issuer_name)])

        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.subject_name)]))
            .issuer_name(issuer)
            .public_key(self.public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=self.days_valid))
        )
        # Add Basic Constraints for CA certs
        if self.is_ca:
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
        return builder.sign(issuer_private_key, hashes.SHA256())

    def get_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    def is_expired(self) -> bool:
        return datetime.datetime.utcnow() > self.certificate.not_valid_after

    @property
    def serial_number(self) -> int:
        return self.certificate.serial_number
